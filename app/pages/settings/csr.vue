<script setup lang="ts">
import { createEd25519Csr } from "~/lib/csr";

const address = ref("");
const fileInput = ref<HTMLInputElement>();
const busy = ref(false);
const message = ref("");

async function generate() {
  const file = fileInput.value?.files?.[0];
  message.value = "";
  if (!file) {
    message.value = "Choose your ed.key file first.";
    return;
  }
  if (file.size > 16384) {
    message.value = "Key file must be no larger than 16 KiB.";
    return;
  }
  busy.value = true;
  try {
    const csr = await createEd25519Csr(await file.text(), address.value);
    const url = URL.createObjectURL(new Blob([csr], { type: "application/pkcs10" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "request.csr";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    message.value = "CSR generated. Only request.csr is downloaded; your key was not uploaded.";
  }
  catch {
    // Never display/log underlying crypto exceptions or file contents.
    message.value = "Could not create CSR. Use an unencrypted Ed25519 PKCS#8 PEM key, a valid Ethereum address, and a browser supporting Ed25519 Web Crypto.";
  }
  finally {
    if (fileInput.value) fileInput.value.value = "";
    busy.value = false;
  }
}
</script>

<template>
  <UDashboardPanel id="csr">
    <template #header>
      <UDashboardNavbar title="Create CSR" />
    </template>
    <template #body>
      <div class="mx-auto w-full max-w-xl space-y-6">
        <SettingsNav />
        <h1 class="text-xl font-semibold">Ed25519 certificate request</h1>
        <p>Your private key stays in this browser. It is never uploaded, logged, or saved by this app. No server-side key files are created.</p>
        <p class="text-sm text-muted">Choose an existing unencrypted PKCS#8 PEM ed.key. Raw hex, secp256k1, encrypted keys, and OpenSSH keys are not supported. The CN address does not prove wallet ownership.</p>
        <form class="space-y-4" @submit.prevent="generate">
          <label class="block space-y-2">
            <span>Ethereum address (CN)</span>
            <input v-model="address" required pattern="0x[0-9a-fA-F]{40}" class="block w-full rounded border p-2" placeholder="0x…" :disabled="busy">
          </label>
          <label class="block space-y-2">
            <span>Private key file (ed.key)</span>
            <input ref="fileInput" type="file" accept=".key,.pem" required class="block w-full" :disabled="busy">
          </label>
          <UButton type="submit" :loading="busy" :disabled="busy">Create and download CSR</UButton>
        </form>
        <p role="status" aria-live="polite">{{ message }}</p>
        <p class="text-sm text-muted">JavaScript cannot guarantee complete memory erasure. Close this page after use and use a trusted device. For valuable wallet keys, prefer offline CSR generation.</p>
      </div>
    </template>
  </UDashboardPanel>
</template>
