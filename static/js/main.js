// Update key input based on cipher type
function updateKeyInput(tab) {
    const cipherSelect = document.getElementById(`${tab}-cipher`);
    const keyInput = document.getElementById(`${tab}-key`);
    const keyLabel = document.getElementById(`${tab}-key-label`);
    const keyHint = document.getElementById(`${tab}-key-hint`);
    
    const cipherType = cipherSelect.value;
    
    // Hide RSA, DSA, and ECC keygen buttons by default
    const rsaKeygenGroup = document.getElementById(`${tab === 'encrypt' ? 'rsa-keygen-group' : 'rsa-keygen-group-decrypt'}`);
    const dsaKeygenGroup = document.getElementById(`${tab === 'encrypt' ? 'dsa-keygen-group' : 'dsa-keygen-group-decrypt'}`);
    const eccKeygenGroup = document.getElementById(`${tab === 'encrypt' ? 'ecc-keygen-group' : 'ecc-keygen-group-decrypt'}`);
    if (rsaKeygenGroup) {
        rsaKeygenGroup.style.display = 'none';
    }
    if (dsaKeygenGroup) {
        dsaKeygenGroup.style.display = 'none';
    }
    if (eccKeygenGroup) {
        eccKeygenGroup.style.display = 'none';
    }
    
    if (cipherType === 'caesar') {
        keyLabel.textContent = 'Kaydırma Değeri (Tam Sayı):';
        keyInput.placeholder = 'Kaydırma değeri girin (örn: 3)';
        keyHint.textContent = 'Tam sayı kaydırma değeri girin (örn: 3)';
        keyInput.rows = 3;
    } else if (cipherType === 'hill') {
        keyLabel.textContent = 'Anahtar Matrisi (JSON):';
        keyInput.placeholder = '2x2 için [[3,3],[2,5]] veya 3x3 için [[1,2,3],[4,5,6],[7,8,9]]';
        keyHint.textContent = '2x2 veya 3x3 matrisi JSON dizisi olarak girin. Örnek: [[3,3],[2,5]]';
        keyInput.rows = 3;
    } else if (cipherType === 'vigenere') {
        keyLabel.textContent = 'Anahtar Kelime:';
        keyInput.placeholder = 'Anahtar kelime girin (örn: ANAHTAR)';
        keyHint.textContent = 'Anahtar kelime dizisi girin (örn: ANAHTAR)';
        keyInput.rows = 3;
    } else if (cipherType === 'vernam') {
        keyLabel.textContent = 'Anahtar (Harf Dizisi):';
        keyInput.placeholder = 'Örn: SECRET';
        keyHint.textContent = 'Harflerden oluşan bir anahtar girin. Harf dışı karakterler yok sayılır.';
        keyInput.rows = 3;
    } else if (cipherType === 'playfair') {
        keyLabel.textContent = 'Anahtar Kelime:';
        keyInput.placeholder = 'Örn: MONARCHY';
        keyHint.textContent = 'Playfair için anahtar kelime girin (I/J birleştirilir).';
        keyInput.rows = 3;
    } else if (cipherType === 'route') {
        keyLabel.textContent = 'Sütun Sayısı (Tam Sayı):';
        keyInput.placeholder = 'Örn: 5';
        keyHint.textContent = 'Route için sütun sayısı girin (örn: 5).';
        keyInput.rows = 3;
    } else if (cipherType === 'affine') {
        keyLabel.textContent = 'Anahtar (a,b):';
        keyInput.placeholder = 'Örn: 5,8';
        keyHint.textContent = "Affine için 'a,b' girin. gcd(a,26)=1 olmalı (örn: 5,8).";
        keyInput.rows = 3;
    } else if (cipherType === 'rail_fence') {
        keyLabel.textContent = 'Ray Sayısı (Tam Sayı):';
        keyInput.placeholder = 'Örn: 3';
        keyHint.textContent = 'Rail Fence için ray sayısı girin (>=2).';
        keyInput.rows = 3;
    } else if (cipherType === 'columnar') {
        keyLabel.textContent = 'Anahtar Kelime:';
        keyInput.placeholder = 'Örn: ZEBRA';
        keyHint.textContent = 'Columnar için anahtar kelime girin (en az 2 karakter).';
        keyInput.rows = 3;
    } else if (cipherType === 'aes_library' || cipherType === 'aes_manual') {
        keyLabel.textContent = 'Anahtar:';
        keyInput.placeholder = 'AES anahtarı girin (örn: mySecretKey123)';
        keyHint.textContent = 'AES için anahtar girin. Kütüphaneli: base64 çıktı, Kütüphanesiz: hex çıktı.';
        keyInput.rows = 3;
    } else if (cipherType === 'des_library' || cipherType === 'des_manual') {
        keyLabel.textContent = 'Anahtar:';
        keyInput.placeholder = 'DES anahtarı girin (örn: myKey123)';
        keyHint.textContent = 'DES için anahtar girin. Kütüphaneli: base64 çıktı, Kütüphanesiz: hex çıktı.';
        keyInput.rows = 3;
    } else if (cipherType === 'rsa_library') {
        if (tab === 'encrypt') {
            keyLabel.textContent = 'Public Key (PEM format):';
            keyInput.placeholder = 'RSA public key\'i PEM formatında yapıştırın...';
            keyHint.textContent = 'RSA şifreleme için public key gerekir. Anahtar çifti oluştur butonunu kullanabilirsiniz.';
            keyInput.rows = 5;
        } else {
            keyLabel.textContent = 'Private Key (PEM format):';
            keyInput.placeholder = 'RSA private key\'i PEM formatında yapıştırın...';
            keyHint.textContent = 'RSA deşifreleme için private key gerekir. Anahtar çifti oluştur butonunu kullanabilirsiniz.';
            keyInput.rows = 5;
        }
        if (rsaKeygenGroup) {
            rsaKeygenGroup.style.display = 'block';
        }
    } else if (cipherType === 'dsa_library') {
        if (tab === 'encrypt') {
            keyLabel.textContent = 'Public Key (PEM format):';
            keyInput.placeholder = 'DSA public key\'i PEM formatında yapıştırın...';
            keyHint.textContent = 'DSA şifreleme için public key gerekir. Anahtar çifti oluştur butonunu kullanabilirsiniz.';
            keyInput.rows = 5;
        } else {
            keyLabel.textContent = 'Private Key (PEM format):';
            keyInput.placeholder = 'DSA private key\'i PEM formatında yapıştırın...';
            keyHint.textContent = 'DSA deşifreleme için private key gerekir. Anahtar çifti oluştur butonunu kullanabilirsiniz.';
            keyInput.rows = 5;
        }
        if (dsaKeygenGroup) {
            dsaKeygenGroup.style.display = 'block';
        }
    } else if (cipherType === 'ecc_library') {
        if (tab === 'encrypt') {
            keyLabel.textContent = 'Public Key (PEM format):';
            keyInput.placeholder = 'ECC public key\'i PEM formatında yapıştırın...';
            keyHint.textContent = 'ECC şifreleme için public key gerekir. Anahtar çifti oluştur butonunu kullanabilirsiniz.';
            keyInput.rows = 5;
        } else {
            keyLabel.textContent = 'Private Key (PEM format):';
            keyInput.placeholder = 'ECC private key\'i PEM formatında yapıştırın...';
            keyHint.textContent = 'ECC deşifreleme için private key gerekir. Anahtar çifti oluştur butonunu kullanabilirsiniz.';
            keyInput.rows = 5;
        }
        if (eccKeygenGroup) {
            eccKeygenGroup.style.display = 'block';
        }
    } else {
        keyInput.rows = 3;
    }
}

// Switch between encrypt and decrypt tabs
function switchTab(tab, buttonElement) {
    // Update tab buttons
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });
    if (buttonElement) {
        buttonElement.classList.add('active');
    } else {
        // Find the button by tab name
        const buttons = document.querySelectorAll('.tab-button');
        buttons.forEach(btn => {
            if (btn.textContent.toLowerCase().includes(tab)) {
                btn.classList.add('active');
            }
        });
    }
    
    // Update tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(`${tab}-tab`).classList.add('active');
    
    // Hide error messages
    hideError();
}

// Show error message
function showError(message) {
    const errorBox = document.getElementById('error-message');
    errorBox.textContent = message;
    errorBox.style.display = 'block';
    setTimeout(() => {
        errorBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 100);
}

// Hide error message
function hideError() {
    const errorBox = document.getElementById('error-message');
    errorBox.style.display = 'none';
}

// Show success message
function showSuccess(message) {
    const errorBox = document.getElementById('error-message');
    errorBox.textContent = message;
    errorBox.className = 'success-box';
    errorBox.style.display = 'block';
    setTimeout(() => {
        errorBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 100);
    
    // Reset to error box style after 5 seconds
    setTimeout(() => {
        errorBox.className = 'error-box';
    }, 5000);
}

// Encrypt message
async function encryptMessage() {
    hideError();
    
    const message = document.getElementById('encrypt-message').value.trim();
    const cipherType = document.getElementById('encrypt-cipher').value;
    const key = document.getElementById('encrypt-key').value.trim();
    
    // Validation
    if (!message) {
        showError('Lütfen şifrelenecek bir mesaj girin.');
        return;
    }
    
    if (!key) {
        showError('Lütfen bir anahtar girin.');
        return;
    }
    
    // Prepare key for Hill cipher
    let processedKey = key;
    if (cipherType === 'hill') {
        try {
            // Validate JSON format
            JSON.parse(key);
            processedKey = key;
        } catch (e) {
            showError('Hill şifresi için geçersiz JSON formatı. Format: [[a,b],[c,d]] kullanın');
            return;
        }
    }
    
    try {
        const response = await fetch('/api/encrypt', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                message: message,
                cipher_type: cipherType,
                key: processedKey
            })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            // Show result
            document.getElementById('encrypt-original').textContent = data.original_message;
            document.getElementById('encrypt-encrypted').textContent = data.encrypted_message;
            
            // Show execution time for AES, DES, RSA, DSA, and ECC
            const isAESorDESorRSAorDSAorECC = cipherType.startsWith('aes_') || cipherType.startsWith('des_') || cipherType === 'rsa_library' || cipherType === 'dsa_library' || cipherType === 'ecc_library';
            if (isAESorDESorRSAorDSAorECC && data.execution_time_ms !== undefined) {
                const timeElement = document.getElementById('encrypt-time');
                const timeItem = document.getElementById('encrypt-time-item');
                timeElement.textContent = data.execution_time_ms + ' ms';
                timeItem.style.display = 'block';
            } else {
                document.getElementById('encrypt-time-item').style.display = 'none';
            }
            
            document.getElementById('encrypt-result').style.display = 'block';
            document.getElementById('encrypt-result').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            
            // Automatically populate decrypt tab with encrypted message
            document.getElementById('decrypt-message').value = data.encrypted_message;
            document.getElementById('decrypt-cipher').value = cipherType;
            document.getElementById('decrypt-key').value = key;
            updateKeyInput('decrypt');
            
            // Automatically switch to decrypt tab
            const decryptButton = document.querySelectorAll('.tab-button')[1];
            switchTab('decrypt', decryptButton);
            
            // Show notification
            showSuccess('Şifrelenmiş mesaj kopyalandı! Deşifreleme sekmesine geçildi.');
        } else {
            showError(data.error || 'Şifreleme başarısız oldu.');
        }
    } catch (error) {
        showError('Ağ hatası: ' + error.message);
    }
}

// Decrypt message
async function decryptMessage() {
    hideError();
    
    const encryptedMessage = document.getElementById('decrypt-message').value.trim();
    const cipherType = document.getElementById('decrypt-cipher').value;
    const key = document.getElementById('decrypt-key').value.trim();
    
    // Validation
    if (!encryptedMessage) {
        showError('Lütfen şifrelenmiş bir mesaj girin.');
        return;
    }
    
    if (!key) {
        showError('Lütfen bir anahtar girin.');
        return;
    }
    
    // Prepare key for Hill cipher
    let processedKey = key;
    if (cipherType === 'hill') {
        try {
            // Validate JSON format
            JSON.parse(key);
            processedKey = key;
        } catch (e) {
            showError('Hill şifresi için geçersiz JSON formatı. Format: [[a,b],[c,d]] kullanın');
            return;
        }
    }
    
    try {
        const response = await fetch('/api/decrypt', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                encrypted_message: encryptedMessage,
                cipher_type: cipherType,
                key: processedKey
            })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            // Show result
            document.getElementById('decrypt-encrypted').textContent = data.encrypted_message;
            document.getElementById('decrypt-decrypted').textContent = data.decrypted_message;
            
            // Show execution time for AES, DES, RSA, DSA, and ECC
            const isAESorDESorRSAorDSAorECC = cipherType.startsWith('aes_') || cipherType.startsWith('des_') || cipherType === 'rsa_library' || cipherType === 'dsa_library' || cipherType === 'ecc_library';
            if (isAESorDESorRSAorDSAorECC && data.execution_time_ms !== undefined) {
                const timeElement = document.getElementById('decrypt-time');
                const timeItem = document.getElementById('decrypt-time-item');
                timeElement.textContent = data.execution_time_ms + ' ms';
                timeItem.style.display = 'block';
            } else {
                document.getElementById('decrypt-time-item').style.display = 'none';
            }
            
            document.getElementById('decrypt-result').style.display = 'block';
            document.getElementById('decrypt-result').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        } else {
            showError(data.error || 'Deşifreleme başarısız oldu.');
        }
    } catch (error) {
        showError('Ağ hatası: ' + error.message);
    }
}

// Generate RSA key pair
async function generateRSAKeys(tab) {
    hideError();
    
    try {
        const response = await fetch('/api/rsa/generate-keys', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                key_size: 2048
            })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            const keyInput = document.getElementById(`${tab}-key`);
            const keyLabel = document.getElementById(`${tab}-key-label`);
            
            // Clean the keys to ensure proper format
            const publicKey = data.public_key.trim();
            const privateKey = data.private_key.trim();
            
            // Verify keys have proper PEM delimiters
            if (!publicKey.includes('BEGIN PUBLIC KEY') || !publicKey.includes('END PUBLIC KEY')) {
                showError('Oluşturulan public key formatı geçersiz.');
                return;
            }
            
            if (!privateKey.includes('BEGIN PRIVATE KEY') || !privateKey.includes('END PRIVATE KEY')) {
                showError('Oluşturulan private key formatı geçersiz.');
                return;
            }
            
            if (tab === 'encrypt') {
                // For encryption, use public key
                keyInput.value = publicKey;
                showSuccess('RSA anahtar çifti oluşturuldu! Public key anahtar alanına yapıştırıldı.');
                
                // Store private key for later use
                if (!document.getElementById('rsa-private-key-storage')) {
                    const storage = document.createElement('textarea');
                    storage.id = 'rsa-private-key-storage';
                    storage.style.display = 'none';
                    document.body.appendChild(storage);
                }
                document.getElementById('rsa-private-key-storage').value = privateKey;
                
                // Show private key in a modal-like display
                showRSAKeyModal('Private Key (Deşifreleme için saklayın):', privateKey);
                
            } else {
                // For decryption, use private key
                keyInput.value = privateKey;
                showSuccess('RSA anahtar çifti oluşturuldu! Private key anahtar alanına yapıştırıldı.');
            }
        } else {
            showError(data.error || 'Anahtar çifti oluşturulamadı.');
        }
    } catch (error) {
        showError('Ağ hatası: ' + error.message);
    }
}

// Show RSA key in a modal
function showRSAKeyModal(title, key) {
    // Remove existing modal if any
    const existingModal = document.getElementById('rsa-key-modal');
    if (existingModal) {
        existingModal.remove();
    }
    
    // Create modal
    const modal = document.createElement('div');
    modal.id = 'rsa-key-modal';
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.5);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 10000;
    `;
    
    const modalContent = document.createElement('div');
    modalContent.style.cssText = `
        background: white;
        padding: 30px;
        border-radius: 12px;
        max-width: 600px;
        width: 90%;
        max-height: 80vh;
        overflow-y: auto;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
    `;
    
    modalContent.innerHTML = `
        <h3 style="margin-bottom: 15px; color: #333;">${title}</h3>
        <textarea id="rsa-key-display" readonly style="
            width: 100%;
            min-height: 200px;
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            resize: vertical;
            margin-bottom: 15px;
        ">${key}</textarea>
        <div style="display: flex; gap: 10px;">
            <button onclick="copyRSAKey()" class="btn-primary" style="flex: 1;">Kopyala</button>
            <button onclick="closeRSAKeyModal()" class="btn-secondary" style="flex: 1;">Kapat</button>
        </div>
    `;
    
    modal.appendChild(modalContent);
    document.body.appendChild(modal);
    
    // Close on background click
    modal.addEventListener('click', function(e) {
        if (e.target === modal) {
            closeRSAKeyModal();
        }
    });
}

// Copy RSA key to clipboard
function copyRSAKey() {
    const keyDisplay = document.getElementById('rsa-key-display');
    keyDisplay.select();
    keyDisplay.setSelectionRange(0, 99999); // For mobile devices
    
    try {
        document.execCommand('copy');
        showSuccess('Private key kopyalandı!');
    } catch (err) {
        // Fallback for modern browsers
        navigator.clipboard.writeText(keyDisplay.value).then(() => {
            showSuccess('Private key kopyalandı!');
        }).catch(() => {
            showError('Kopyalama başarısız oldu. Lütfen manuel olarak kopyalayın.');
        });
    }
}

// Close RSA key modal
function closeRSAKeyModal() {
    const modal = document.getElementById('rsa-key-modal');
    if (modal) {
        modal.remove();
    }
}

// Generate DSA key pair
async function generateDSAKeys(tab) {
    hideError();
    
    try {
        const response = await fetch('/api/dsa/generate-keys', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                key_size: 2048
            })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            const keyInput = document.getElementById(`${tab}-key`);
            const keyLabel = document.getElementById(`${tab}-key-label`);
            
            // Clean the keys to ensure proper format
            const publicKey = data.public_key.trim();
            const privateKey = data.private_key.trim();
            
            // Verify keys have proper PEM delimiters
            if (!publicKey.includes('BEGIN PUBLIC KEY') || !publicKey.includes('END PUBLIC KEY')) {
                showError('Oluşturulan public key formatı geçersiz.');
                return;
            }
            
            if (!privateKey.includes('BEGIN PRIVATE KEY') || !privateKey.includes('END PRIVATE KEY')) {
                showError('Oluşturulan private key formatı geçersiz.');
                return;
            }
            
            if (tab === 'encrypt') {
                // For encryption, use public key
                keyInput.value = publicKey;
                showSuccess('DSA anahtar çifti oluşturuldu! Public key anahtar alanına yapıştırıldı.');
                
                // Store private key for later use
                if (!document.getElementById('dsa-private-key-storage')) {
                    const storage = document.createElement('textarea');
                    storage.id = 'dsa-private-key-storage';
                    storage.style.display = 'none';
                    document.body.appendChild(storage);
                }
                document.getElementById('dsa-private-key-storage').value = privateKey;
                
                // Show private key in a modal-like display
                showRSAKeyModal('Private Key (Deşifreleme için saklayın):', privateKey);
                
            } else {
                // For decryption, use private key
                keyInput.value = privateKey;
                showSuccess('DSA anahtar çifti oluşturuldu! Private key anahtar alanına yapıştırıldı.');
            }
        } else {
            showError(data.error || 'Anahtar çifti oluşturulamadı.');
        }
    } catch (error) {
        showError('Ağ hatası: ' + error.message);
    }
}

// Generate ECC key pair
async function generateECCKeys(tab) {
    hideError();
    
    try {
        const response = await fetch('/api/ecc/generate-keys', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                curve_name: 'secp256r1'
            })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            const keyInput = document.getElementById(`${tab}-key`);
            const keyLabel = document.getElementById(`${tab}-key-label`);
            
            // Clean the keys to ensure proper format
            const publicKey = data.public_key.trim();
            const privateKey = data.private_key.trim();
            
            // Verify keys have proper PEM delimiters
            if (!publicKey.includes('BEGIN PUBLIC KEY') || !publicKey.includes('END PUBLIC KEY')) {
                showError('Oluşturulan public key formatı geçersiz.');
                return;
            }
            
            if (!privateKey.includes('BEGIN PRIVATE KEY') || !privateKey.includes('END PRIVATE KEY')) {
                showError('Oluşturulan private key formatı geçersiz.');
                return;
            }
            
            if (tab === 'encrypt') {
                // For encryption, use public key
                keyInput.value = publicKey;
                showSuccess('ECC anahtar çifti oluşturuldu! Public key anahtar alanına yapıştırıldı.');
                
                // Store private key for later use
                if (!document.getElementById('ecc-private-key-storage')) {
                    const storage = document.createElement('textarea');
                    storage.id = 'ecc-private-key-storage';
                    storage.style.display = 'none';
                    document.body.appendChild(storage);
                }
                document.getElementById('ecc-private-key-storage').value = privateKey;
                
                // Show private key in a modal-like display
                showRSAKeyModal('Private Key (Deşifreleme için saklayın):', privateKey);
                
            } else {
                // For decryption, use private key
                keyInput.value = privateKey;
                showSuccess('ECC anahtar çifti oluşturuldu! Private key anahtar alanına yapıştırıldı.');
            }
        } else {
            showError(data.error || 'Anahtar çifti oluşturulamadı.');
        }
    } catch (error) {
        showError('Ağ hatası: ' + error.message);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    updateKeyInput('encrypt');
    updateKeyInput('decrypt');
});

