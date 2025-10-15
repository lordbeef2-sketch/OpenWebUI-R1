<script lang="ts">
  import { onMount, createEventDispatcher, getContext } from 'svelte';
  import { toast } from 'svelte-sonner';
  import { WEBUI_BASE_URL } from '$lib/constants';
  const i18n: any = getContext('i18n');
  const dispatch = createEventDispatcher();

  let loading = false;
  let form = {
    ENABLE_HTTPS: false,
    HTTPS_PORT: 8443,
    HTTPS_CERT_PATH: '',
    HTTPS_KEY_PATH: '',
    HTTPS_P12_FILENAME: '',
    WEBUI_HOSTNAME: '',
    WEBUI_URL: ''
  };

  let p12File: File | null = null;
  let p12Password: string = '';

  function onP12Change(e: Event) {
    const input = e.target as HTMLInputElement | null;
    p12File = input && input.files ? input.files[0] : null;
  }

  async function loadConfig() {
    try {
  const r = await fetch(`${WEBUI_BASE_URL}/api/v1/configs/https`, { credentials: 'include' });
      if (!r.ok) throw new Error('Failed to load HTTPS config');
      form = await r.json();
    } catch (e) {
      console.error(e);
      toast.error($i18n.t('Failed to load HTTPS config'));
    }
  }

  async function saveConfig() {
    loading = true;
    try {
      const r = await fetch(`${WEBUI_BASE_URL}/api/v1/configs/https`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(form)
      });
      if (!r.ok) throw new Error('Save failed');
      form = await r.json();
      toast.success($i18n.t('Settings saved successfully!'));
      dispatch('save');
    } catch (e) {
      console.error(e);
      toast.error($i18n.t('Failed to save HTTPS settings'));
    } finally {
      loading = false;
    }
  }

  async function uploadP12() {
    if (!p12File) {
      toast.error($i18n.t('Select a PKCS#12 file first'));
      return;
    }
    const fd = new FormData();
    fd.append('file', p12File);
    if (p12Password) fd.append('password', p12Password);
    loading = true;
    try {
  const r = await fetch(`${WEBUI_BASE_URL}/api/v1/configs/https/upload_p12`, { method: 'POST', body: fd, credentials: 'include' });
      if (!r.ok) throw new Error('Upload failed');
      form = await r.json();
      toast.success($i18n.t('Certificate uploaded and extracted'));
    } catch (e) {
      console.error(e);
      toast.error($i18n.t('Upload failed'));
    } finally {
      loading = false;
    }
  }

  onMount(loadConfig);
</script>

<div class="space-y-6">
  <div>
    <h2 class="font-semibold text-lg">{$i18n.t('HTTPS')}</h2>
    <p class="text-xs text-gray-500 dark:text-gray-400">{$i18n.t('Configure built-in HTTPS with a PKCS#12 (.p12/.pfx) bundle. Restart required to apply changes.')}</p>
  </div>

  <div class="flex items-center gap-3">
    <label class="flex items-center gap-2 cursor-pointer select-none">
      <input type="checkbox" bind:checked={form.ENABLE_HTTPS} class="checkbox checkbox-sm" />
      <span>{$i18n.t('Enable HTTPS')}</span>
    </label>
    <div class="flex items-center gap-2">
  <label for="https-port">{$i18n.t('HTTPS Port')}</label>
  <input id="https-port" class="input input-sm input-bordered w-24" type="number" bind:value={form.HTTPS_PORT} min="1" />
    </div>
  </div>

  <div class="grid gap-4 md:grid-cols-2">
    <div class="space-y-2">
  <label class="font-medium text-sm" for="p12-input">{$i18n.t('PKCS#12 Bundle')}</label>
  <input id="p12-input" type="file" accept=".p12,.pfx" on:change={onP12Change} class="file-input file-input-sm w-full" />
      <input type="password" placeholder={$i18n.t('Password (if any)')} bind:value={p12Password} class="input input-sm input-bordered w-full" />
      <button class="btn btn-sm btn-primary" disabled={loading} on:click={uploadP12}>{$i18n.t('Upload & Extract')}</button>
      {#if form.HTTPS_P12_FILENAME}
        <p class="text-xs text-gray-500">{$i18n.t('Current Bundle')}: {form.HTTPS_P12_FILENAME}</p>
      {/if}
    </div>

    <div class="space-y-2">
  <div class="font-medium text-sm">{$i18n.t('Hostname & Derived Certificate Paths')}</div>
      <div class="flex items-center gap-2">
        <label for="hostname" class="text-xs">{$i18n.t('Hostname')}</label>
        <input id="hostname" class="input input-sm input-bordered w-full" type="text" bind:value={form.WEBUI_HOSTNAME} placeholder={location.hostname} />
      </div>
      <div class="text-xs break-all">{form.HTTPS_CERT_PATH || $i18n.t('None')}</div>
      <div class="text-xs break-all">{form.HTTPS_KEY_PATH || $i18n.t('None')}</div>
      {#if form.WEBUI_URL}
        <div class="text-xs text-gray-500">{$i18n.t('Public URL')}: {form.WEBUI_URL}</div>
      {/if}
      <p class="text-xs text-gray-500">{$i18n.t('Paths are generated on upload and stored in persistent config.')} </p>
    </div>
  </div>

  <div class="flex gap-2">
    <button class="btn btn-sm" on:click={loadConfig} disabled={loading}>{$i18n.t('Reset')}</button>
    <button class="btn btn-sm btn-primary" on:click={saveConfig} disabled={loading}>{$i18n.t('Save')}</button>
  </div>
</div>
