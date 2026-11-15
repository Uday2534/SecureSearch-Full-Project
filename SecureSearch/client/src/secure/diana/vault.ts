import { openVaultState, sealVaultState } from "../crypto";
import { loadEncryptedVault, saveEncryptedVault } from "../vaultStorage";
import { createSecureVaultState, type SecureVaultState } from "./workflow";
import { DianaClient } from "./diana";

export interface UnlockedVault {
  client: DianaClient;
  state: SecureVaultState;
}

function isVaultState(value: unknown): value is SecureVaultState {
  if (!value || typeof value !== "object") return false;
  const state = value as Partial<SecureVaultState>;
  return state.version === 1 &&
    typeof state.dianaState === "string" &&
    typeof state.nextDocumentIndex === "string" &&
    !!state.documentKeys && typeof state.documentKeys === "object" &&
    !!state.trustedLeaves && typeof state.trustedLeaves === "object" &&
    typeof state.trustedRoot === "string";
}

export async function unlockOrCreateVault(passphrase: string): Promise<UnlockedVault> {
  const envelope = await loadEncryptedVault();
  if (!envelope) {
    const created = await createSecureVaultState();
    await saveEncryptedVault(await sealVaultState(created.state, passphrase));
    return created;
  }

  const state = await openVaultState<unknown>(envelope, passphrase);
  if (!isVaultState(state)) throw new Error("Vault data is invalid or from an unsupported version.");
  return { client: DianaClient.restoreState(state.dianaState), state };
}

export async function unlockExistingVault(passphrase: string): Promise<UnlockedVault> {
  const envelope = await loadEncryptedVault();
  if (!envelope) throw new Error("No secure vault exists in this browser yet. Create it from the Upload page first.");
  const state = await openVaultState<unknown>(envelope, passphrase);
  if (!isVaultState(state)) throw new Error("Vault data is invalid or from an unsupported version.");
  return { client: DianaClient.restoreState(state.dianaState), state };
}
