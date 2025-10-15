from urllib.parse import urlparse
from fastapi.middleware.cors import CORSMiddleware

from open_webui.env import log
from open_webui.config import CORS_ALLOW_ORIGIN


def update_cors_from_webui_url(app, webui_url: str):
    """
    Update FastAPI CORSMiddleware origins at runtime to include the origin of the given WEBUI URL.
    - If CORS_ALLOW_ORIGIN is wildcard (["*"]), do nothing.
    - Otherwise, append the new origin if missing and rebuild the middleware stack.
    """
    try:
        current_url = str(webui_url or "")
        parsed = urlparse(current_url) if current_url else None
        origin = (
            f"{parsed.scheme}://{parsed.netloc}"
            if parsed and parsed.scheme and parsed.netloc
            else None
        )

        if not origin:
            return

        # Initialize runtime CORS list from startup config if not present
        if getattr(app.state, "cors_allow_origin", None) is None:
            app.state.cors_allow_origin = list(CORS_ALLOW_ORIGIN)

        # If wildcard is used, nothing to update
        if app.state.cors_allow_origin == ["*"]:
            return

        if origin not in app.state.cors_allow_origin:
            app.state.cors_allow_origin.append(origin)

            # Remove existing CORSMiddleware entries
            app.user_middleware = [
                m for m in app.user_middleware if getattr(m, "cls", None) is not CORSMiddleware
            ]

            # Add the updated CORS middleware
            app.add_middleware(
                CORSMiddleware,
                allow_origins=app.state.cors_allow_origin,
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )

            # Rebuild middleware stack to apply changes immediately
            app.middleware_stack = app.build_middleware_stack()
    except Exception as e:
        log.debug(f"Failed to update CORS origins from WEBUI_URL '{webui_url}': {e}")
