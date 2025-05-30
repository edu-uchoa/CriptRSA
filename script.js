// global variables to public and private keys
let rsaPublicKey, rsaPrivateKey;

// function for user to choose size of the key 
function showKeySizeWarning() {
    const size = parseInt(document.getElementById("keySizeSelect").value);
    const warning = document.getElementById("keySizeWarning");

    if (size === 512) {
        warning.textContent = "⚠️ 512 bits é inseguro! Use apenas para testes.";
        warning.style.color = "red";
    } else if (size === 1024) {
        warning.textContent = "⚠️ 1024 bits é fraco. Evite para dados sensíveis.";
        warning.style.color = "orange";
    } else if (size === 2048) {
        warning.textContent = "✅ 2048 bits é o tamanho ideal para segurança.";
        warning.style.color = "green";
    }
}

async function generateRSAKeys() {
    
    const keySize = parseInt(document.getElementById("keySizeSelect").value);

    // Generate an RSA-OAEP key pair using userchoice-bit modulus and SHA-256 as the hash algorithm
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",                // Algorithm for encryption/decryption
            modulusLength: keySize,             // Key size: 2048 bits (standard and secure)
            publicExponent: new Uint8Array([1, 0, 1]), // Common public exponent (65537)
            hash: "SHA-256"                  // Hash function used with OAEP padding
        },
        true,                                // Keys are exportable (can be converted to text)
        ["encrypt", "decrypt"]              // The key pair will be used for both encryption and decryption
    );

    // Save the generated keys into global variables
    rsaPublicKey = keyPair.publicKey;
    rsaPrivateKey = keyPair.privateKey;

    // Export the public key in SPKI (SubjectPublicKeyInfo) format
    const exportedPub = await window.crypto.subtle.exportKey("spki", rsaPublicKey);
    
    // Export the private key in PKCS#8 format
    const exportedPriv = await window.crypto.subtle.exportKey("pkcs8", rsaPrivateKey);

    // Convert the exported public key from binary (ArrayBuffer) to Base64 string
    document.getElementById("publicKeyOutput").value = 
        btoa(String.fromCharCode(...new Uint8Array(exportedPub)));

    // Convert the exported private key from binary (ArrayBuffer) to Base64 string
    document.getElementById("privateKeyOutput").value = 
        btoa(String.fromCharCode(...new Uint8Array(exportedPriv)));
}

async function rsaEncrypt() {
    // Get the plaintext message from the input field
    const plaintext = document.getElementById("rsaPlainText").value;

    // Create a TextEncoder to convert the string to a Uint8Array (binary)
    const encoder = new TextEncoder();

    // Encrypt the encoded plaintext using the public key and RSA-OAEP
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },      // Must match the key algorithm
        rsaPublicKey,              // Use the previously generated public key
        encoder.encode(plaintext)  // Convert string to binary before encryption
    );

    // Convert the encrypted ArrayBuffer to Base64 string and display it
    document.getElementById("rsaEncryptedText").value = 
        btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}


async function rsaDecrypt() {
    // Get the encrypted text (in Base64 format) from the input field
    const encryptedText = document.getElementById("rsaEncryptedText").value;

    // Decode the Base64 text back into binary (Uint8Array)
    const encryptedBytes = new Uint8Array(
        [...atob(encryptedText)].map(c => c.charCodeAt(0))
    );

    // Decrypt the binary data using the private key and RSA-OAEP
    const decrypted = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },   // Must match the key algorithm
        rsaPrivateKey,          // Use the previously generated private key
        encryptedBytes          // The encrypted message in binary format
    );

    // Convert the decrypted binary data back to a string
    const decoder = new TextDecoder();
    document.getElementById("rsaDecryptedText").value = decoder.decode(decrypted);
}
