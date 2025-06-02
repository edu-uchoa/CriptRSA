// Variáveis globais para chaves e originais em Base64
let rsaPublicKey = null;
let rsaPrivateKey = null;
let originalPublicKeyBase64 = "";
let originalPrivateKeyBase64 = "";

// Atualiza a chave pública a partir do Base64 digitado/colado pelo usuário
async function updatePublicKeyFromInput() {
  const base64Pub = document.getElementById("publicKeyOutput").value.trim();
  if (!base64Pub) {
    rsaPublicKey = null;
    document.getElementById("publicKeyOutput").style.borderColor = "";
    return;
  }
  try {
    const binaryDer = Uint8Array.from(atob(base64Pub), c => c.charCodeAt(0));
    rsaPublicKey = await window.crypto.subtle.importKey(
      "spki",
      binaryDer.buffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["encrypt"]
    );

    // Validar se chave corresponde à original
    if (base64Pub === originalPublicKeyBase64) {
      document.getElementById("publicKeyOutput").style.borderColor = "green";
    } else {
      document.getElementById("publicKeyOutput").style.borderColor = "orange"; // chave diferente da original
    }
  } catch (e) {
    rsaPublicKey = null;
    document.getElementById("publicKeyOutput").style.borderColor = "red";
    console.error("Chave pública inválida:", e);
  }
}

// Atualiza a chave privada a partir do Base64 digitado/colado pelo usuário
async function updatePrivateKeyFromInput() {
  const base64Priv = document.getElementById("privateKeyOutput").value.trim();
  if (!base64Priv) {
    rsaPrivateKey = null;
    document.getElementById("privateKeyOutput").style.borderColor = "";
    return;
  }
  try {
    const binaryDer = Uint8Array.from(atob(base64Priv), c => c.charCodeAt(0));
    rsaPrivateKey = await window.crypto.subtle.importKey(
      "pkcs8",
      binaryDer.buffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["decrypt"]
    );

    // Validar se chave corresponde à original
    if (base64Priv === originalPrivateKeyBase64) {
      document.getElementById("privateKeyOutput").style.borderColor = "green";
    } else {
      document.getElementById("privateKeyOutput").style.borderColor = "orange"; // chave diferente da original
    }
  } catch (e) {
    rsaPrivateKey = null;
    document.getElementById("privateKeyOutput").style.borderColor = "red";
    console.error("Chave privada inválida:", e);
  }
}

// Função para mostrar aviso do tamanho da chave
function showKeySizeWarning() {
  const size = parseInt(document.getElementById("keySizeSelect").value);
  const warning = document.getElementById("keySizeWarning");

  if (size === 2048) {
    warning.textContent = "✅ 2048 bits é o tamanho ideal para segurança.";
    warning.style.color = "green";
  } else if (size === 3072) {
    warning.textContent = "🔒 3072 bits oferece segurança extra para longo prazo.";
    warning.style.color = "darkgreen";
  } else if (size === 4096) {
    warning.textContent = "🛡️ 4096 bits é muito seguro, porém mais lento.";
    warning.style.color = "blue";
  }
}

// Função para gerar par de chaves RSA
async function generateRSAKeys() {
  const keySize = parseInt(document.getElementById("keySizeSelect").value);

  if (![2048, 3072, 4096].includes(keySize)) {
    alert("⚠️ Tamanho de chave inválido.");
    return;
  }

  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: keySize,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );

  rsaPublicKey = keyPair.publicKey;
  rsaPrivateKey = keyPair.privateKey;

  const exportedPub = await window.crypto.subtle.exportKey("spki", rsaPublicKey);
  const exportedPriv = await window.crypto.subtle.exportKey("pkcs8", rsaPrivateKey);

  originalPublicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPub)));
  originalPrivateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPriv)));

  document.getElementById("publicKeyOutput").value = originalPublicKeyBase64;
  document.getElementById("privateKeyOutput").value = originalPrivateKeyBase64;

  // Reset border colors (chaves agora são originais e válidas)
  document.getElementById("publicKeyOutput").style.borderColor = "green";
  document.getElementById("privateKeyOutput").style.borderColor = "green";
}

// Função para criptografar
async function rsaEncrypt() {
  const publicKeyTextarea = document.getElementById("publicKeyOutput");
  const publicKeyText = publicKeyTextarea.value.trim();

  if (publicKeyText === "") {
    alert("❗ Geração de chave necessária antes da criptografia.");
    return;
  }

  if (publicKeyText !== originalPublicKeyBase64) {
    alert("❗ Chave pública incorreta necessária antes da criptografia.");
    return;
  }

  if (!rsaPublicKey) {
    alert("❗ Chave pública inválida.");
    return;
  }

  const plaintext = document.getElementById("rsaPlainText").value;
  const encoder = new TextEncoder();

  try {
    const encrypted = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      rsaPublicKey,
      encoder.encode(plaintext)
    );

    document.getElementById("rsaEncryptedText").value =
      btoa(String.fromCharCode(...new Uint8Array(encrypted)));
  } catch (e) {
    alert("Erro durante a criptografia: " + e.message);
  }
}

// Função para descriptografar
async function rsaDecrypt() {
  const privateKeyTextarea = document.getElementById("privateKeyOutput");
  const privateKeyText = privateKeyTextarea.value.trim();

  if (privateKeyText === "") {
    alert("❗ Geração de chave necessária antes da descriptografia.");
    return;
  }

  if (privateKeyText !== originalPrivateKeyBase64) {
    alert("❗ Chave privada incorreta necessária antes da descriptografia.");
    return;
  }

  if (!rsaPrivateKey) {
    alert("❗ Chave privada inválida.");
    return;
  }

  const encryptedText = document.getElementById("rsaEncryptedText").value;
  if (!encryptedText) {
    alert("❗ Informe o texto criptografado para descriptografar.");
    return;
  }

  try {
    const encryptedBytes = new Uint8Array(
      [...atob(encryptedText)].map(c => c.charCodeAt(0))
    );

    const decrypted = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      rsaPrivateKey,
      encryptedBytes
    );

    const decoder = new TextDecoder();
    document.getElementById("rsaDecryptedText").value = decoder.decode(decrypted);
  } catch (e) {
    alert("Erro durante a descriptografia: " + e.message);
  }
}

// Event listeners para atualizar as chaves quando o usuário altera as textareas
document.getElementById("publicKeyOutput").addEventListener("input", () => {
  updatePublicKeyFromInput();
});
document.getElementById("privateKeyOutput").addEventListener("input", () => {
  updatePrivateKeyFromInput();
});
