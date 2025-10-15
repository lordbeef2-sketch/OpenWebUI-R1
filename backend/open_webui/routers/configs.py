import logging
from fastapi import APIRouter, Depends, Request, HTTPException, UploadFile, File, Form
from pydantic import BaseModel, ConfigDict
import aiohttp

from typing import Optional
import os, tempfile, subprocess
from pathlib import Path
from urllib.parse import urlparse
from fastapi.middleware.cors import CORSMiddleware

from open_webui.utils.auth import get_admin_user, get_verified_user
from open_webui.config import get_config, save_config
from open_webui.config import BannerModel
from open_webui.config import (
    ENABLE_HTTPS,
    HTTPS_PORT,
    HTTPS_CERT_PATH,
    HTTPS_KEY_PATH,
    HTTPS_P12_FILENAME,
)
from open_webui.utils.cors import update_cors_from_webui_url

from open_webui.utils.tools import (
    get_tool_server_data,
    get_tool_server_url,
    set_tool_servers,
)
from open_webui.utils.mcp.client import MCPClient

from open_webui.env import SRC_LOG_LEVELS

from open_webui.utils.oauth import (
    get_discovery_urls,
    get_oauth_client_info_with_dynamic_client_registration,
    encrypt_data,
    decrypt_data,
    OAuthClientInformationFull,
)
from mcp.shared.auth import OAuthMetadata

router = APIRouter()

log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["MAIN"])


############################
# ImportConfig
############################


class ImportConfigForm(BaseModel):
    config: dict


@router.post("/import", response_model=dict)
async def import_config(form_data: ImportConfigForm, user=Depends(get_admin_user)):
    save_config(form_data.config)
    return get_config()


############################
# ExportConfig
############################


@router.get("/export", response_model=dict)
async def export_config(user=Depends(get_admin_user)):
    return get_config()


############################
# Connections Config
############################


class ConnectionsConfigForm(BaseModel):
    ENABLE_DIRECT_CONNECTIONS: bool
    ENABLE_BASE_MODELS_CACHE: bool


@router.get("/connections", response_model=ConnectionsConfigForm)
async def get_connections_config(request: Request, user=Depends(get_admin_user)):
    return {
        "ENABLE_DIRECT_CONNECTIONS": request.app.state.config.ENABLE_DIRECT_CONNECTIONS,
        "ENABLE_BASE_MODELS_CACHE": request.app.state.config.ENABLE_BASE_MODELS_CACHE,
    }


@router.post("/connections", response_model=ConnectionsConfigForm)
async def set_connections_config(
    request: Request,
    form_data: ConnectionsConfigForm,
    user=Depends(get_admin_user),
):
    request.app.state.config.ENABLE_DIRECT_CONNECTIONS = (
        form_data.ENABLE_DIRECT_CONNECTIONS
    )
    request.app.state.config.ENABLE_BASE_MODELS_CACHE = (
        form_data.ENABLE_BASE_MODELS_CACHE
    )

    return {
        "ENABLE_DIRECT_CONNECTIONS": request.app.state.config.ENABLE_DIRECT_CONNECTIONS,
        "ENABLE_BASE_MODELS_CACHE": request.app.state.config.ENABLE_BASE_MODELS_CACHE,
    }


class OAuthClientRegistrationForm(BaseModel):
    url: str
    client_id: str
    client_name: Optional[str] = None


@router.post("/oauth/clients/register")
async def register_oauth_client(
    request: Request,
    form_data: OAuthClientRegistrationForm,
    type: Optional[str] = None,
    user=Depends(get_admin_user),
):
    try:
        oauth_client_id = form_data.client_id
        if type:
            oauth_client_id = f"{type}:{form_data.client_id}"

        oauth_client_info = (
            await get_oauth_client_info_with_dynamic_client_registration(
                request, oauth_client_id, form_data.url
            )
        )
        return {
            "status": True,
            "oauth_client_info": encrypt_data(
                oauth_client_info.model_dump(mode="json")
            ),
        }
    except Exception as e:
        log.debug(f"Failed to register OAuth client: {e}")
        raise HTTPException(
            status_code=400,
            detail=f"Failed to register OAuth client",
        )


############################
# ToolServers Config
############################


class ToolServerConnection(BaseModel):
    url: str
    path: str
    type: Optional[str] = "openapi"  # openapi, mcp
    auth_type: Optional[str]
    key: Optional[str]
    config: Optional[dict]

    model_config = ConfigDict(extra="allow")


class ToolServersConfigForm(BaseModel):
    TOOL_SERVER_CONNECTIONS: list[ToolServerConnection]


@router.get("/tool_servers", response_model=ToolServersConfigForm)
async def get_tool_servers_config(request: Request, user=Depends(get_admin_user)):
    return {
        "TOOL_SERVER_CONNECTIONS": request.app.state.config.TOOL_SERVER_CONNECTIONS,
    }


@router.post("/tool_servers", response_model=ToolServersConfigForm)
async def set_tool_servers_config(
    request: Request,
    form_data: ToolServersConfigForm,
    user=Depends(get_admin_user),
):
    request.app.state.config.TOOL_SERVER_CONNECTIONS = [
        connection.model_dump() for connection in form_data.TOOL_SERVER_CONNECTIONS
    ]

    await set_tool_servers(request)

    for connection in request.app.state.config.TOOL_SERVER_CONNECTIONS:
        server_type = connection.get("type", "openapi")
        if server_type == "mcp":
            server_id = connection.get("info", {}).get("id")
            auth_type = connection.get("auth_type", "none")
            if auth_type == "oauth_2.1" and server_id:
                try:
                    oauth_client_info = connection.get("info", {}).get(
                        "oauth_client_info", ""
                    )
                    oauth_client_info = decrypt_data(oauth_client_info)

                    await request.app.state.oauth_client_manager.add_client(
                        f"{server_type}:{server_id}",
                        OAuthClientInformationFull(**oauth_client_info),
                    )
                except Exception as e:
                    log.debug(f"Failed to add OAuth client for MCP tool server: {e}")
                    continue

    return {
        "TOOL_SERVER_CONNECTIONS": request.app.state.config.TOOL_SERVER_CONNECTIONS,
    }


@router.post("/tool_servers/verify")
async def verify_tool_servers_config(
    request: Request, form_data: ToolServerConnection, user=Depends(get_admin_user)
):
    """
    Verify the connection to the tool server.
    """
    try:
        if form_data.type == "mcp":
            if form_data.auth_type == "oauth_2.1":
                discovery_urls = get_discovery_urls(form_data.url)
                for discovery_url in discovery_urls:
                    log.debug(
                        f"Trying to fetch OAuth 2.1 discovery document from {discovery_url}"
                    )
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            discovery_url
                        ) as oauth_server_metadata_response:
                            if oauth_server_metadata_response.status == 200:
                                try:
                                    oauth_server_metadata = (
                                        OAuthMetadata.model_validate(
                                            await oauth_server_metadata_response.json()
                                        )
                                    )
                                    return {
                                        "status": True,
                                        "oauth_server_metadata": oauth_server_metadata.model_dump(
                                            mode="json"
                                        ),
                                    }
                                except Exception as e:
                                    log.info(
                                        f"Failed to parse OAuth 2.1 discovery document: {e}"
                                    )
                                    raise HTTPException(
                                        status_code=400,
                                        detail=f"Failed to parse OAuth 2.1 discovery document from {discovery_url}",
                                    )

                raise HTTPException(
                    status_code=400,
                    detail=f"Failed to fetch OAuth 2.1 discovery document from {discovery_urls}",
                )
            else:
                try:
                    client = MCPClient()
                    headers = None

                    token = None
                    if form_data.auth_type == "bearer":
                        token = form_data.key
                    elif form_data.auth_type == "session":
                        token = request.state.token.credentials
                    elif form_data.auth_type == "system_oauth":
                        try:
                            if request.cookies.get("oauth_session_id", None):
                                token = await request.app.state.oauth_manager.get_oauth_token(
                                    user.id,
                                    request.cookies.get("oauth_session_id", None),
                                )
                        except Exception as e:
                            pass

                    if token:
                        headers = {"Authorization": f"Bearer {token}"}

                    await client.connect(form_data.url, headers=headers)
                    specs = await client.list_tool_specs()
                    return {
                        "status": True,
                        "specs": specs,
                    }
                except Exception as e:
                    log.debug(f"Failed to create MCP client: {e}")
                    raise HTTPException(
                        status_code=400,
                        detail=f"Failed to create MCP client",
                    )
                finally:
                    if client:
                        await client.disconnect()
        else:  # openapi
            token = None
            if form_data.auth_type == "bearer":
                token = form_data.key
            elif form_data.auth_type == "session":
                token = request.state.token.credentials
            elif form_data.auth_type == "system_oauth":
                try:
                    if request.cookies.get("oauth_session_id", None):
                        token = await request.app.state.oauth_manager.get_oauth_token(
                            user.id,
                            request.cookies.get("oauth_session_id", None),
                        )
                except Exception as e:
                    pass

            url = get_tool_server_url(form_data.url, form_data.path)
            return await get_tool_server_data(token, url)
    except HTTPException as e:
        raise e
    except Exception as e:
        log.debug(f"Failed to connect to the tool server: {e}")
        raise HTTPException(
            status_code=400,
            detail=f"Failed to connect to the tool server",
        )


############################
# CodeInterpreterConfig
############################
class CodeInterpreterConfigForm(BaseModel):
    ENABLE_CODE_EXECUTION: bool
    CODE_EXECUTION_ENGINE: str
    CODE_EXECUTION_JUPYTER_URL: Optional[str]
    CODE_EXECUTION_JUPYTER_AUTH: Optional[str]
    CODE_EXECUTION_JUPYTER_AUTH_TOKEN: Optional[str]
    CODE_EXECUTION_JUPYTER_AUTH_PASSWORD: Optional[str]
    CODE_EXECUTION_JUPYTER_TIMEOUT: Optional[int]
    ENABLE_CODE_INTERPRETER: bool
    CODE_INTERPRETER_ENGINE: str
    CODE_INTERPRETER_PROMPT_TEMPLATE: Optional[str]
    CODE_INTERPRETER_JUPYTER_URL: Optional[str]
    CODE_INTERPRETER_JUPYTER_AUTH: Optional[str]
    CODE_INTERPRETER_JUPYTER_AUTH_TOKEN: Optional[str]
    CODE_INTERPRETER_JUPYTER_AUTH_PASSWORD: Optional[str]
    CODE_INTERPRETER_JUPYTER_TIMEOUT: Optional[int]


@router.get("/code_execution", response_model=CodeInterpreterConfigForm)
async def get_code_execution_config(request: Request, user=Depends(get_admin_user)):
    return {
        "ENABLE_CODE_EXECUTION": request.app.state.config.ENABLE_CODE_EXECUTION,
        "CODE_EXECUTION_ENGINE": request.app.state.config.CODE_EXECUTION_ENGINE,
        "CODE_EXECUTION_JUPYTER_URL": request.app.state.config.CODE_EXECUTION_JUPYTER_URL,
        "CODE_EXECUTION_JUPYTER_AUTH": request.app.state.config.CODE_EXECUTION_JUPYTER_AUTH,
        "CODE_EXECUTION_JUPYTER_AUTH_TOKEN": request.app.state.config.CODE_EXECUTION_JUPYTER_AUTH_TOKEN,
        "CODE_EXECUTION_JUPYTER_AUTH_PASSWORD": request.app.state.config.CODE_EXECUTION_JUPYTER_AUTH_PASSWORD,
        "CODE_EXECUTION_JUPYTER_TIMEOUT": request.app.state.config.CODE_EXECUTION_JUPYTER_TIMEOUT,
        "ENABLE_CODE_INTERPRETER": request.app.state.config.ENABLE_CODE_INTERPRETER,
        "CODE_INTERPRETER_ENGINE": request.app.state.config.CODE_INTERPRETER_ENGINE,
        "CODE_INTERPRETER_PROMPT_TEMPLATE": request.app.state.config.CODE_INTERPRETER_PROMPT_TEMPLATE,
        "CODE_INTERPRETER_JUPYTER_URL": request.app.state.config.CODE_INTERPRETER_JUPYTER_URL,
        "CODE_INTERPRETER_JUPYTER_AUTH": request.app.state.config.CODE_INTERPRETER_JUPYTER_AUTH,
        "CODE_INTERPRETER_JUPYTER_AUTH_TOKEN": request.app.state.config.CODE_INTERPRETER_JUPYTER_AUTH_TOKEN,
        "CODE_INTERPRETER_JUPYTER_AUTH_PASSWORD": request.app.state.config.CODE_INTERPRETER_JUPYTER_AUTH_PASSWORD,
        "CODE_INTERPRETER_JUPYTER_TIMEOUT": request.app.state.config.CODE_INTERPRETER_JUPYTER_TIMEOUT,
    }


@router.post("/code_execution", response_model=CodeInterpreterConfigForm)
async def set_code_execution_config(
    request: Request, form_data: CodeInterpreterConfigForm, user=Depends(get_admin_user)
):

    request.app.state.config.ENABLE_CODE_EXECUTION = form_data.ENABLE_CODE_EXECUTION

    request.app.state.config.CODE_EXECUTION_ENGINE = form_data.CODE_EXECUTION_ENGINE
    request.app.state.config.CODE_EXECUTION_JUPYTER_URL = (
        form_data.CODE_EXECUTION_JUPYTER_URL
    )
    request.app.state.config.CODE_EXECUTION_JUPYTER_AUTH = (
        form_data.CODE_EXECUTION_JUPYTER_AUTH
    )
    request.app.state.config.CODE_EXECUTION_JUPYTER_AUTH_TOKEN = (
        form_data.CODE_EXECUTION_JUPYTER_AUTH_TOKEN
    )
    request.app.state.config.CODE_EXECUTION_JUPYTER_AUTH_PASSWORD = (
        form_data.CODE_EXECUTION_JUPYTER_AUTH_PASSWORD
    )
    request.app.state.config.CODE_EXECUTION_JUPYTER_TIMEOUT = (
        form_data.CODE_EXECUTION_JUPYTER_TIMEOUT
    )

    request.app.state.config.ENABLE_CODE_INTERPRETER = form_data.ENABLE_CODE_INTERPRETER
    request.app.state.config.CODE_INTERPRETER_ENGINE = form_data.CODE_INTERPRETER_ENGINE
    request.app.state.config.CODE_INTERPRETER_PROMPT_TEMPLATE = (
        form_data.CODE_INTERPRETER_PROMPT_TEMPLATE
    )

    request.app.state.config.CODE_INTERPRETER_JUPYTER_URL = (
        form_data.CODE_INTERPRETER_JUPYTER_URL
    )

    request.app.state.config.CODE_INTERPRETER_JUPYTER_AUTH = (
        form_data.CODE_INTERPRETER_JUPYTER_AUTH
    )

    request.app.state.config.CODE_INTERPRETER_JUPYTER_AUTH_TOKEN = (
        form_data.CODE_INTERPRETER_JUPYTER_AUTH_TOKEN
    )
    request.app.state.config.CODE_INTERPRETER_JUPYTER_AUTH_PASSWORD = (
        form_data.CODE_INTERPRETER_JUPYTER_AUTH_PASSWORD
    )
    request.app.state.config.CODE_INTERPRETER_JUPYTER_TIMEOUT = (
        form_data.CODE_INTERPRETER_JUPYTER_TIMEOUT
    )

    return {
        "ENABLE_CODE_EXECUTION": request.app.state.config.ENABLE_CODE_EXECUTION,
        "CODE_EXECUTION_ENGINE": request.app.state.config.CODE_EXECUTION_ENGINE,
        "CODE_EXECUTION_JUPYTER_URL": request.app.state.config.CODE_EXECUTION_JUPYTER_URL,
        "CODE_EXECUTION_JUPYTER_AUTH": request.app.state.config.CODE_EXECUTION_JUPYTER_AUTH,
        "CODE_EXECUTION_JUPYTER_AUTH_TOKEN": request.app.state.config.CODE_EXECUTION_JUPYTER_AUTH_TOKEN,
        "CODE_EXECUTION_JUPYTER_AUTH_PASSWORD": request.app.state.config.CODE_EXECUTION_JUPYTER_AUTH_PASSWORD,
        "CODE_EXECUTION_JUPYTER_TIMEOUT": request.app.state.config.CODE_EXECUTION_JUPYTER_TIMEOUT,
        "ENABLE_CODE_INTERPRETER": request.app.state.config.ENABLE_CODE_INTERPRETER,
        "CODE_INTERPRETER_ENGINE": request.app.state.config.CODE_INTERPRETER_ENGINE,
        "CODE_INTERPRETER_PROMPT_TEMPLATE": request.app.state.config.CODE_INTERPRETER_PROMPT_TEMPLATE,
        "CODE_INTERPRETER_JUPYTER_URL": request.app.state.config.CODE_INTERPRETER_JUPYTER_URL,
        "CODE_INTERPRETER_JUPYTER_AUTH": request.app.state.config.CODE_INTERPRETER_JUPYTER_AUTH,
        "CODE_INTERPRETER_JUPYTER_AUTH_TOKEN": request.app.state.config.CODE_INTERPRETER_JUPYTER_AUTH_TOKEN,
        "CODE_INTERPRETER_JUPYTER_AUTH_PASSWORD": request.app.state.config.CODE_INTERPRETER_JUPYTER_AUTH_PASSWORD,
        "CODE_INTERPRETER_JUPYTER_TIMEOUT": request.app.state.config.CODE_INTERPRETER_JUPYTER_TIMEOUT,
    }


############################
# SetDefaultModels
############################
class ModelsConfigForm(BaseModel):
    DEFAULT_MODELS: Optional[str]
    MODEL_ORDER_LIST: Optional[list[str]]


@router.get("/models", response_model=ModelsConfigForm)
async def get_models_config(request: Request, user=Depends(get_admin_user)):
    return {
        "DEFAULT_MODELS": request.app.state.config.DEFAULT_MODELS,
        "MODEL_ORDER_LIST": request.app.state.config.MODEL_ORDER_LIST,
    }

############################
# HTTPS Config (added)
############################


class HTTPSConfigForm(BaseModel):
    ENABLE_HTTPS: bool
    HTTPS_PORT: int
    HTTPS_CERT_PATH: Optional[str]
    HTTPS_KEY_PATH: Optional[str]
    HTTPS_P12_FILENAME: Optional[str]
    WEBUI_HOSTNAME: Optional[str] = None
    WEBUI_URL: Optional[str] = None


@router.get("/https", response_model=HTTPSConfigForm)
async def get_https_config(request: Request, user=Depends(get_admin_user)):
    current_url = str(request.app.state.config.WEBUI_URL or "")
    parsed = urlparse(current_url) if current_url else None
    hostname = parsed.hostname if parsed else None

    return {
        "ENABLE_HTTPS": request.app.state.config.ENABLE_HTTPS,
        "HTTPS_PORT": request.app.state.config.HTTPS_PORT,
        "HTTPS_CERT_PATH": request.app.state.config.HTTPS_CERT_PATH,
        "HTTPS_KEY_PATH": request.app.state.config.HTTPS_KEY_PATH,
        "HTTPS_P12_FILENAME": request.app.state.config.HTTPS_P12_FILENAME,
        "WEBUI_HOSTNAME": hostname,
        "WEBUI_URL": current_url,
    }


@router.post("/https", response_model=HTTPSConfigForm)
async def set_https_config(
    request: Request,
    form_data: HTTPSConfigForm,
    user=Depends(get_admin_user),
):
    request.app.state.config.ENABLE_HTTPS = form_data.ENABLE_HTTPS
    request.app.state.config.HTTPS_PORT = form_data.HTTPS_PORT
    if form_data.HTTPS_CERT_PATH:
        request.app.state.config.HTTPS_CERT_PATH = form_data.HTTPS_CERT_PATH
    if form_data.HTTPS_KEY_PATH:
        request.app.state.config.HTTPS_KEY_PATH = form_data.HTTPS_KEY_PATH
    if form_data.HTTPS_P12_FILENAME is not None:
        request.app.state.config.HTTPS_P12_FILENAME = form_data.HTTPS_P12_FILENAME
    # Optionally update global WEBUI_URL here for a single source of truth
    try:
        if form_data.WEBUI_HOSTNAME:
            host = form_data.WEBUI_HOSTNAME.strip()
            port = int(form_data.HTTPS_PORT)
            port_part = "" if port == 443 else f":{port}"
            request.app.state.config.WEBUI_URL = f"https://{host}{port_part}"
        elif form_data.WEBUI_URL:
            request.app.state.config.WEBUI_URL = form_data.WEBUI_URL
    except Exception as e:
        log.debug(f"Failed to update WEBUI_URL from HTTPS settings: {e}")
    update_cors_from_webui_url(request.app, request.app.state.config.WEBUI_URL)
    current_url = str(request.app.state.config.WEBUI_URL or "")
    parsed = urlparse(current_url) if current_url else None
    hostname = parsed.hostname if parsed else None

    return {
        "ENABLE_HTTPS": request.app.state.config.ENABLE_HTTPS,
        "HTTPS_PORT": request.app.state.config.HTTPS_PORT,
        "HTTPS_CERT_PATH": request.app.state.config.HTTPS_CERT_PATH,
        "HTTPS_KEY_PATH": request.app.state.config.HTTPS_KEY_PATH,
        "HTTPS_P12_FILENAME": request.app.state.config.HTTPS_P12_FILENAME,
        "WEBUI_HOSTNAME": hostname,
        "WEBUI_URL": current_url,
    }


@router.post("/https/upload_p12", response_model=HTTPSConfigForm)
async def upload_https_p12(
    request: Request,
    file: UploadFile = File(...),
    password: Optional[str] = Form(None),
    user=Depends(get_admin_user),
):
    filename = file.filename
    if not filename.lower().endswith((".p12", ".pfx")):
        raise HTTPException(status_code=400, detail="Only .p12/.pfx files are supported")

    ssl_dir = Path(os.environ.get("DATA_DIR", "data")) / "ssl"
    ssl_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".p12") as tmp:
        contents = await file.read()
        tmp.write(contents)
        tmp_path = Path(tmp.name)

    cert_path = ssl_dir / "cert.pem"
    key_path = ssl_dir / "key.pem"

    def _run_extract(use_legacy: bool):
        # Build commands for cert and key extraction
        base_args = ["openssl", "pkcs12"]
        if use_legacy:
            # OpenSSL 3.x: needed for older PKCS#12 using legacy KDF/ciphers
            base_args = base_args + ["-legacy"]

        cmd_cert = base_args + [
            "-in",
            str(tmp_path),
            "-clcerts",
            "-nokeys",
            "-out",
            str(cert_path),
        ]
        if password:
            cmd_cert.extend(["-passin", f"pass:{password}"])

        cmd_key = base_args + [
            "-in",
            str(tmp_path),
            "-nocerts",
            "-nodes",
            "-out",
            str(key_path),
        ]
        if password:
            cmd_key.extend(["-passin", f"pass:{password}"])

        r1 = subprocess.run(cmd_cert, check=False, capture_output=True, text=True)
        if r1.returncode != 0:
            return False, r1.stderr or r1.stdout
        r2 = subprocess.run(cmd_key, check=False, capture_output=True, text=True)
        if r2.returncode != 0:
            return False, r2.stderr or r2.stdout
        return True, ""

    try:
        ok, err = _run_extract(use_legacy=False)
        if not ok:
            # Retry with -legacy for OpenSSL 3.x / old PKCS#12
            ok2, err2 = _run_extract(use_legacy=True)
            if not ok2:
                # Cleanup partial files on failure
                if cert_path.exists():
                    cert_path.unlink()
                if key_path.exists():
                    key_path.unlink()
                detail = (
                    "Failed to extract certificate/key. "
                    "Tried both standard and -legacy modes. "
                    "OpenSSL output: " + (err2 or err)
                )
                raise HTTPException(status_code=400, detail=detail)
    except FileNotFoundError as e:
        # openssl not found on PATH
        if cert_path.exists():
            cert_path.unlink()
        if key_path.exists():
            key_path.unlink()
        raise HTTPException(
            status_code=400,
            detail=(
                "OpenSSL executable not found. Please install OpenSSL and ensure 'openssl' is in PATH."
            ),
        ) from e
    finally:
        try:
            tmp_path.unlink()
        except Exception:
            pass

    request.app.state.config.HTTPS_CERT_PATH = str(cert_path)
    request.app.state.config.HTTPS_KEY_PATH = str(key_path)
    request.app.state.config.HTTPS_P12_FILENAME = filename

    current_url = str(request.app.state.config.WEBUI_URL or "")
    parsed = urlparse(current_url) if current_url else None
    hostname = parsed.hostname if parsed else None

    return {
        "ENABLE_HTTPS": request.app.state.config.ENABLE_HTTPS,
        "HTTPS_PORT": request.app.state.config.HTTPS_PORT,
        "HTTPS_CERT_PATH": request.app.state.config.HTTPS_CERT_PATH,
        "HTTPS_KEY_PATH": request.app.state.config.HTTPS_KEY_PATH,
        "HTTPS_P12_FILENAME": request.app.state.config.HTTPS_P12_FILENAME,
        "WEBUI_HOSTNAME": hostname,
        "WEBUI_URL": current_url,
    }


@router.post("/models", response_model=ModelsConfigForm)
async def set_models_config(
    request: Request, form_data: ModelsConfigForm, user=Depends(get_admin_user)
):
    request.app.state.config.DEFAULT_MODELS = form_data.DEFAULT_MODELS
    request.app.state.config.MODEL_ORDER_LIST = form_data.MODEL_ORDER_LIST
    return {
        "DEFAULT_MODELS": request.app.state.config.DEFAULT_MODELS,
        "MODEL_ORDER_LIST": request.app.state.config.MODEL_ORDER_LIST,
    }


class PromptSuggestion(BaseModel):
    title: list[str]
    content: str


class SetDefaultSuggestionsForm(BaseModel):
    suggestions: list[PromptSuggestion]


@router.post("/suggestions", response_model=list[PromptSuggestion])
async def set_default_suggestions(
    request: Request,
    form_data: SetDefaultSuggestionsForm,
    user=Depends(get_admin_user),
):
    data = form_data.model_dump()
    request.app.state.config.DEFAULT_PROMPT_SUGGESTIONS = data["suggestions"]
    return request.app.state.config.DEFAULT_PROMPT_SUGGESTIONS


############################
# SetBanners
############################


class SetBannersForm(BaseModel):
    banners: list[BannerModel]


@router.post("/banners", response_model=list[BannerModel])
async def set_banners(
    request: Request,
    form_data: SetBannersForm,
    user=Depends(get_admin_user),
):
    data = form_data.model_dump()
    request.app.state.config.BANNERS = data["banners"]
    return request.app.state.config.BANNERS


@router.get("/banners", response_model=list[BannerModel])
async def get_banners(
    request: Request,
    user=Depends(get_verified_user),
):
    return request.app.state.config.BANNERS
