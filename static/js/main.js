// Update key input based on cipher type
function updateKeyInput(tab) {
    const cipherSelect = document.getElementById(`${tab}-cipher`);
    const keyInput = document.getElementById(`${tab}-key`);
    const keyLabel = document.getElementById(`${tab}-key-label`);
    const keyHint = document.getElementById(`${tab}-key-hint`);
    
    const cipherType = cipherSelect.value;
    
    if (cipherType === 'caesar') {
        keyLabel.textContent = 'Kaydırma Değeri (Tam Sayı):';
        keyInput.type = 'text';
        keyInput.placeholder = 'Kaydırma değeri girin (örn: 3)';
        keyHint.textContent = 'Tam sayı kaydırma değeri girin (örn: 3)';
    } else if (cipherType === 'hill') {
        keyLabel.textContent = 'Anahtar Matrisi (JSON):';
        keyInput.type = 'text';
        keyInput.placeholder = '2x2 için [[3,3],[2,5]] veya 3x3 için [[1,2,3],[4,5,6],[7,8,9]]';
        keyHint.textContent = '2x2 veya 3x3 matrisi JSON dizisi olarak girin. Örnek: [[3,3],[2,5]]';
    } else if (cipherType === 'vigenere') {
        keyLabel.textContent = 'Anahtar Kelime:';
        keyInput.type = 'text';
        keyInput.placeholder = 'Anahtar kelime girin (örn: ANAHTAR)';
        keyHint.textContent = 'Anahtar kelime dizisi girin (örn: ANAHTAR)';
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
            document.getElementById('decrypt-result').style.display = 'block';
            document.getElementById('decrypt-result').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        } else {
            showError(data.error || 'Deşifreleme başarısız oldu.');
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

