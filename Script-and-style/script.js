'use strict';
let countdown;




document.addEventListener('DOMContentLoaded', function () {

    function validateCardNumber(cardNumber) {
        // Remove spaces and non-digit characters from the card number
        const strippedNumber = cardNumber.replace(/\D/g, '');

        // Use a regular expression to check for a valid credit card pattern (13 to 16 digits)
        const validFormat = /^\d{13,16}$/;
        if (!validFormat.test(strippedNumber)) {
            return false;
        }

        // Apply the Luhn algorithm to validate the card number
        let sum = 0;
        let digit;
        let shouldDouble = false;
        for (let i = strippedNumber.length - 1; i >= 0; i--) {
            digit = parseInt(strippedNumber.charAt(i), 10);
            if (shouldDouble) {
                if ((digit *= 2) > 9) digit -= 9;
            }
            sum += digit;
            shouldDouble = !shouldDouble;
        }
        return sum % 10 === 0;
    }

    // Test the function
    const cardNumberToValidate = document.getElementById('cardNumber');
    const element = document.getElementById('errorCard');
    let isValid = false;

    cardNumberToValidate.addEventListener('input', function (event) {
        const input = event.target.value;
        isValid = validateCardNumber(input);

        if (isValid) {
            element.style.display = 'none';
        }
    });

    cardNumberToValidate.addEventListener('blur', function () {
        if (!isValid) {
            element.style.display = 'block';
        }
    });

});


// Front-end code for preventing form submission by bots (Honeypot captcha)
function checkBots(formId,event) {
    // Check if all required fields are filled
    const form = document.getElementById(formId);
    const requiredFields = form.querySelectorAll('[required]');
    let allFieldsFilled = true;

    requiredFields.forEach(field => {
        if (field.value.trim() === '') {
            allFieldsFilled = false;
        }
    });

    // Proceed with checkBots logic only if all required fields are filled
    if (allFieldsFilled) {
       checkPots(event);


        function checkPots(event) {
            // Check if the honeypot field is filled
            if (document.getElementById("honeypot").value !== "") {
                // If the honeypot field is filled, it's likely a bot, so prevent form submission
                event.preventDefault();
                alert("Oops, something went wrong. Please try again.");
            }
            else {
                alert("No bots. Honeypot captcha verified!!!!");
            }
        }
    } else {
        alert('Please fill in all required fields before submitting.');
    }
}



document.addEventListener('DOMContentLoaded', function () {
    console.log("DOM content loaded");

    const generateOTPButton = document.getElementById('generateOTP');
    const verifyOTPButton = document.getElementById('verifyOTP');
    const otpInput = document.getElementById('otpInput');

    let generatedOTP = null; // Variable to store the generated OTP
    let timeoutID; // Variable to store the timeout ID
    let countdown;
    

    // Event listener for "Generate OTP" button click
    generateOTPButton.addEventListener('click', function () {
        generatedOTP = generateRandomOTP(); // Generate a new random 6-digit OTP
        alert('OTP sent successfully. Please check console. '); // Display generated OTP (for demo purposes)
        console.log('Generated OTP: '+generatedOTP); 

        // Set a time limit (in milliseconds) for the OTP display (e.g., 5 seconds)
        const timeLimit = 60000;
        startCountdown();


        function startCountdown() {
            
            //var generateOTPButton = document.getElementById("generateOTP");
            generateOTPButton.disabled = true;
        
            var seconds = 60;
            countdown = setInterval(function () {
                generateOTPButton.innerHTML = "Resend OTP in " + seconds + "s";
                seconds--;
        
                if (seconds < 0) {
                    clearInterval(countdown);
                    generateOTPButton.innerHTML = "Generate OTP";
                    generateOTPButton.disabled = false;
                }
            }, 1000);
        }


        // Clear the OTP after the specified time limit
        timeoutID = setTimeout(function () {
            clearOTP();
        }, timeLimit);
    });

    // Event listener for "Verify OTP" button click
    verifyOTPButton.addEventListener('click', function () {
        const enteredOTP = otpInput.value;
        generateOTPButton.disabled = false;

        if (enteredOTP == generatedOTP) {
            confirm('Valid OTP! MFA Authentication Successful. Proceed payment.'); 
            clearInterval(countdown);
            generateOTPButton.innerHTML = "Generate OTP";
            generateOTPButton.disabled = false;

            document.getElementById('otp').style.display = "block";
            clearTimeout(timeoutID); // Clear the timeout when OTP is verified
        } else {
            otpInput.value = "";
            confirm("Invalid OTP! Authentication Failed. Payment can't be processed."); 
        }
    });

    // Function to clear the generated OTP
    function clearOTP() {
        generatedOTP = null;
        confirm("OTP Expired! Please generate a new one.");
        
    }

    // Function to generate a random 6-digit OTP
    function generateRandomOTP() {
        return Math.floor(100000 + Math.random() * 900000); // Generate a 6-digit OTP
    }
});


// Update the 'handlePaymentForm' function to store CVV in local storage
function handlePaymentForm() {
    var cvvValue = document.getElementById('cvv').value;

    // Store CVV in local storage
    sessionStorage.setItem('cvv', cvvValue);

    // Redirect to symmEnc.html
    window.location.href = 'symmEnc.html';
}

// Retrieve and display the stored CVV in symmEnc.html
document.addEventListener('DOMContentLoaded', function () {
    // Check if the current page is symmEnc.html
    if (window.location.href.includes('symmEnc.html')) {
        // Retrieve the stored CVV from local storage
        const storedCVV = sessionStorage.getItem('cvv');

        // Display the stored CVV in the appropriate span
        if (storedCVV) {
            document.getElementById('cvv1').textContent = storedCVV;
        }
    }
});

// Function to handle AES encryption with a key derivation function (KDF)
async function encrypt() {
    try {

        const commonKeyInput = document.getElementById('commonKey').value;
        if(commonKeyInput==''){
            alert("Please enter key to encrypt.");
        }
        else{
        // Display the result section
        document.getElementById('result_enc').style.display = 'block';
        // Get the CVV and common key from the form
        const cvvInput = document.getElementById('cvv1').textContent; // Use textContent to get the displayed CVV
        

        // Use a key derivation function (PBKDF2) to derive bits from the passphrase
        const encoder = new TextEncoder();
        const salt = crypto.getRandomValues(new Uint8Array(16)); // Generate a random salt
        const passwordKey = await crypto.subtle.importKey('raw', encoder.encode(commonKeyInput), { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
        const derivedBits = await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
            passwordKey,
            256
        );

        // Use the derived bits to create an AES-CBC key
        const key = await crypto.subtle.importKey('raw', derivedBits, { name: 'AES-CBC', length: 256 }, false, ['encrypt']);

        // Encrypt the CVV using AES-CBC
        const encryptedBuffer = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: crypto.getRandomValues(new Uint8Array(16)) }, key, encoder.encode(cvvInput));

        // Convert the encrypted result to a hexadecimal string
        const encryptedHex = Array.from(new Uint8Array(encryptedBuffer)).map(byte => byte.toString(16).padStart(2, '0')).join('');

        // Store the encrypted CVV and salt in local storage
        localStorage.setItem('encryptedCVV', encryptedHex);
        localStorage.setItem('encryptionSalt', Array.from(salt).map(byte => byte.toString(16).padStart(2, '0')).join(''));

        // Store the encrypted CVV and salt in session storage
        sessionStorage.setItem('encryptedCVV', encryptedHex);
        sessionStorage.setItem('encryptionSalt', Array.from(salt).map(byte => byte.toString(16).padStart(2, '0')).join(''));


        // Display the encrypted CVV
        displayEncryptedCVV(encryptedHex);}
    } catch (error) {
        console.error("Error during AES encryption:", error);
    }
}

// Function to display the encrypted CVV
function displayEncryptedCVV(encryptedCVV) {
    const encryptedCVVElement = document.getElementById('encryptedCVV');
    if (encryptedCVVElement) {
        encryptedCVVElement.textContent = encryptedCVV;
    } else {
        console.error("Error: Could not find the 'encryptedCVV' element.");
    }

    const userKeyElement = document.getElementById('usedKey');
    const commonKeyInput = document.getElementById('commonKey');
    if (userKeyElement && commonKeyInput) {
        userKeyElement.textContent = commonKeyInput.value;
        const ckeyip=document.getElementById('commonKey').value;
        sessionStorage.setItem('cKey',ckeyip);
    } else {
        console.error("Error: Could not find the 'userKey' or 'commonKey' element.");
    }
}

// Update the 'copyToRSA' function to store CVV in local storage
function copyToRSA() {
    var cvvText = document.getElementById('encryptedCVV').textContent;

    // Store CVV in local storage
    sessionStorage.setItem('cvvAES', cvvText);

    // Redirect to RsaEncr.html
    window.location.href = 'RsaEncr.html';
}

// Retrieve and display the encrypted CVV in RsaEncr.html
document.addEventListener('DOMContentLoaded', function () {
    // Check if the current page is RsaEncr.html
    if (window.location.href.includes('RsaEncr.html')) {
        // Retrieve the stored CVV from local storage
        const storedCVVText = sessionStorage.getItem('cvvAES');

        // Display the stored CVV in the appropriate span
        if (storedCVVText) {
            document.getElementById('symmetricCiphertext').textContent = storedCVVText;
        }
    }
});

// Utility function to convert ArrayBuffer to base64
function arrayBufferToBase64(buffer) {
    const binary = String.fromCharCode.apply(null, new Uint8Array(buffer));
    return btoa(binary);
}

// Utility function to convert base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
    try {
        const binaryString = window.atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    } catch (error) {
        console.error("Error decoding base64:", error);
        return null;
    }
}


// Utility function to convert string to Uint8Array
function stringToUint8Array(str) {
    const encoder = new TextEncoder();
    return encoder.encode(str);
}


// Global variable to store the generated RSA key pair
let globalKeyPair;

// Function to generate an RSA key pair
async function generateRSAKeyPair() {
    if (globalKeyPair) {
        return globalKeyPair;
    }

    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );

    const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

    // Store the private key in local storage
    localStorage.setItem('privateKey', arrayBufferToBase64(privateKey));

    globalKeyPair = {
        publicKey: arrayBufferToBase64(publicKey),
        privateKey: arrayBufferToBase64(privateKey),
    };

    return globalKeyPair;
}

// Function to handle RSA encryption
async function encrypt1() {
    // Display the result section
    document.getElementById('result').style.display = 'block';

    // Retrieve the symmetric ciphertext from local storage
    const symmetricCiphertext = sessionStorage.getItem('cvvAES');

    // Check if the symmetric ciphertext is available
    if (!symmetricCiphertext) {
        console.error("Symmetric ciphertext not found.");
        return;
    }

    // Generate an RSA key pair
    const keyPair = await generateRSAKeyPair();

    // Encrypt the symmetric ciphertext using the RSA public key
    const rsaCiphertext = await encryptWithRSA(symmetricCiphertext, keyPair.publicKey);

    // Display the public key and RSA ciphertext
    document.getElementById('publicKey').value = keyPair.publicKey;
    document.getElementById('rsaCiphertext').value = rsaCiphertext;
}

// Function to encrypt data with RSA
async function encryptWithRSA(data, publicKey) {
    const importedPublicKey = await crypto.subtle.importKey(
        "spki",
        base64ToArrayBuffer(publicKey),
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
    );

    const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        importedPublicKey,
        stringToUint8Array(data)
    );

    const encryptedCVV = arrayBufferToBase64(encryptedBuffer);
    return encryptedCVV;
}

// Update the 'copyToDecrypt' function to store CVV in local storage
function copyToDecrypt() {
    

    // Redirect to RsaDecr.html
    window.location.href = 'RsaDecr.html';
}

// Retrieve and display the encrypted CVV in RsaDecr.html
document.addEventListener('DOMContentLoaded', function () {
    // Check if the current page is RsaDecr.html
    if (window.location.href.includes('RsaDecr.html')) {
        // Retrieve the stored RSA Ciphertext from local storage
        const storedCiphertext = localStorage.getItem('rsaCiphertext');

        // Display the stored RSA Ciphertext in the appropriate span
        if (storedCiphertext) {
            document.getElementById('encryptedValue').textContent = storedCiphertext;
        }
    }
});

// Function to decrypt data with RSA
async function decryptWithRSA(data, privateKey) {
    try {
        const privateKeyBuffer = base64ToArrayBuffer(privateKey);

        const importedPrivateKey = await crypto.subtle.importKey(
            "pkcs8",
            privateKeyBuffer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt"]
        );

        const ciphertextBuffer = base64ToArrayBuffer(data);
        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            importedPrivateKey,
            ciphertextBuffer
        );

        const decryptedCVV = new TextDecoder().decode(decryptedBuffer);
        return decryptedCVV;
    } catch (error) {
        console.error("RSA decryption error:", error.message || error);

        if (error instanceof DOMException && error.name === "DataCloneError") {
            console.error("Private key format error. Make sure the private key is in the correct format.");
        }

        return null;
    }
}

// Function to decrypt data with RSA
async function decrypt() {
    try {
        document.getElementById('decB').style.display = 'none';
        document.getElementById('decryptRsa').style.display = 'block';
        // Retrieve the RSA ciphertext from the span
        const rsaCiphertext = document.getElementById('encryptedValue').textContent;

        // Ensure RSA ciphertext is available
        if (!rsaCiphertext) {
            console.error("RSA ciphertext not found.");
            return;
        }

        // Retrieve the private key from local storage
        const storedPrivateKey = localStorage.getItem('privateKey');

        // Ensure private key is available
        if (!storedPrivateKey) {
            console.error("Private key not found.");
            return;
        }

        // Decrypt the RSA ciphertext
        const decryptedCVV = await decryptWithRSA(rsaCiphertext, storedPrivateKey);

        // Display the private key and decrypted CVV
        document.getElementById('privateKey').value = storedPrivateKey;
        document.getElementById('decryptedValue').value = decryptedCVV;
    } catch (error) {
        console.error("Error during decryption:", error);
    }
}

function copyToSym() {

    // Redirect to RsaDecr.html
    window.location.href = 'symmDec.html';
}

// Retrieve and display the decrypted CVV in symmDec.html
document.addEventListener('DOMContentLoaded', function () {
    // Check if the current page is RsaEncr.html
    if (window.location.href.includes('symmDec.html')) {
        // Retrieve the stored CVV from local storage
        const storedCVVText = sessionStorage.getItem('cvvAES');

        // Display the stored CVV in the appropriate span
        if (storedCVVText) {
            document.getElementById('rsaDecryptedCVV').textContent = storedCVVText;
        }
    }
});

// Function to handle AES decryption with a key derivation function (KDF)
async function dec1() {
    try {
        // Retrieve the encrypted CVV and salt from session storage
        const encryptedHex = sessionStorage.getItem('encryptedCVV');
        const saltHex = sessionStorage.getItem('encryptionSalt');

        if (!encryptedHex || !saltHex) {
            console.error('No encrypted data found.');
            return;
        }

        // Convert hex strings back to Uint8Arrays
        const encryptedBuffer = new Uint8Array(encryptedHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

        // Get the common key from the form
        const commonKeyInput = document.getElementById('commonKey1').value;

        // Use a key derivation function (PBKDF2) to derive bits from the passphrase
        const encoder = new TextEncoder();
        const passwordKey = await crypto.subtle.importKey('raw', encoder.encode(commonKeyInput), { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
        const derivedBits = await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
            passwordKey,
            256
        );

        // Use the derived bits to create an AES-CBC key
        const key = await crypto.subtle.importKey('raw', derivedBits, { name: 'AES-CBC', length: 256 }, false, ['decrypt']);

        // Decrypt the CVV using AES-CBC
        const decryptedBuffer = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: salt }, key, encryptedBuffer);

        // Convert the decrypted result to a string
        const decryptedCVV = new TextDecoder().decode(decryptedBuffer);

        // Display the decrypted CVV
        console.log('Decrypted CVV:', decryptedCVV);
    } catch (error) {
        console.error("Error during AES decryption:", error);
    }
}


async function dec2()
{
    
    // Get the common key from the form
    const commonKeyInput = document.getElementById('commonKey1').value;
    const cKeyInput=sessionStorage.getItem("cKey");

    if(commonKeyInput==cKeyInput){
        document.getElementById('decb').style.display='none';
        document.getElementById('result1').style.display='block';
    const itemcvv=sessionStorage.getItem("cvv");
    document.getElementById("ORIGINALCVV").textContent= itemcvv;}
    else{
        alert("Key mismatch. Please try again.");
    }
}


function cancel(){
    
    document.getElementById('result_enc').style.display='none';
    document.getElementById('commonKey').value='';

}

function cancel1(){
    document.getElementById('result').style.display='none';

}

function cancel2(){
    document.getElementById('decB').style.display = 'block';
    document.getElementById('decryptRsa').style.display='none';
}

function cancel3(){
    document.getElementById('decb').style.display='block';
    document.getElementById('result1').style.display='none';
    document.getElementById('commonKey').value='';

}

function proc(){
    var cipherText = document.getElementById('rsaCiphertext').value;

    // Store RSA Ciphertext in local storage with a consistent key
    localStorage.setItem('rsaCiphertext', cipherText);
 
  if (confirm("Do you want to Decrypt?")) {
    copyToDecrypt();
  } else {
    window.location.href='lm2.html';
  }
}

function procu(){
    if (confirm("Do you want to Exit?")) {
        window.location.href='https://www.google.com';
      } else {
        if (confirm("Do you want to Decrypt?")) {
            copyToDecrypt();
          } else {
            window.location.href='lm2.html';
          }
      } 
}





//Code for RSA and AES encryption

/*let publicKey;



document.addEventListener('DOMContentLoaded', function () {
    // ... (your existing code)

    const encryptButton = document.getElementById('encryptButton');

    encryptButton.addEventListener('click', function () {
        // Simulate cvv encryption with AES for demo purposes
        const cardNumber = document.getElementById('cvv');
        const aesKey = window.crypto.getRandomValues(new Uint8Array(16));

        encryptWithAES(cardNumber, aesKey).then(encrypted => {
            console.log('Encrypted card number (AES):', encrypted);
            // Generate an RSA key pair (public and private key)
        });
        crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: "SHA-256"
            },
            true, // Whether the key is extractable (for export)
            ["encrypt", "decrypt"] // Key usage
        )
            .then(function (keyPair) {
                // Use the public key for encryption
                publicKey = keyPair.publicKey;
                generateRSAEncryptedKey(aesKey);
            })
            .catch(function (err) {
                console.error(err);
            });
        // Perform RSA encryption of the AES key
        if (publicKey) {
            const encryptedKey = encryptWithRSA(aesKey, publicKey);
            encryptedKey.then(result => {
                console.log('Encrypted AES key (RSA):', result);
                // Simulated output, in practice, this data should be sent securely to the server
            }).catch(err => {
                console.error('RSA encryption failed:', err);
            });
        } else {
            console.error('Public key not available');
        }
    });


});

//AES Encryption
function encryptWithAES(text, key) {
    const encodedText = new TextEncoder().encode(text);
    return window.crypto.subtle.importKey('raw', key, 'AES-GCM', true, ['encrypt'])
        .then(encodedKey => {
            return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: window.crypto.getRandomValues(new Uint8Array(12)) }, encodedKey, encodedText);
        })
        .then(encrypted => {
            const encryptedArray = new Uint8Array(encrypted);
            return Array.from(encryptedArray).map(byte => ('0' + byte.toString(16)).slice(-2)).join('');
        });
}

// RSA Encryption function
function encryptWithRSA(text, publicKey) {
    const encodedText = new TextEncoder().encode(text);
    return window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, encodedText)
        .then(encrypted => {
            const encryptedArray = new Uint8Array(encrypted);
            return Array.from(encryptedArray).map(byte => ('0' + byte.toString(16)).slice(-2)).join('');
        });
}*/

/*document.addEventListener('DOMContentLoaded', function () {
    const cvvForm = document.getElementById('payment-form');
    const encryptButton = document.getElementById('encryptButton');
    const cvvInput = document.getElementById('cvv1');
    const encryptedCvv = document.getElementById('encryptedCvv');
    const symmetricKey = document.getElementById('symmetricKey');

    encryptButton.addEventListener('click', function () {
        // Simulating card number encryption with AES for demo purposes
        const cvv = cvvInput.value;
        const aesKey = window.crypto.getRandomValues(new Uint8Array(16));

        encryptCVVWithAES(cvv, aesKey).then(result => {
            encryptedCvv.textContent = `Encrypted CVV: ${result.encryptedCVV}`;
            symmetricKey.textContent = `Symmetric Key (AES): ${result.key}`;
        }).catch(err => {
            console.error('CVV encryption failed:', err);
        });
    });

    function encryptCVVWithAES(text, key) {
        const encodedText = new TextEncoder().encode(text);
        return window.crypto.subtle.importKey('raw', key, 'AES-GCM', true, ['encrypt'])
            .then(encodedKey => {
                return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: window.crypto.getRandomValues(new Uint8Array(12)) }, encodedKey, encodedText);
            })
            .then(encrypted => {
                const encryptedArray = new Uint8Array(encrypted);
                const encryptedCVV = Array.from(encryptedArray).map(byte => ('0' + byte.toString(16)).slice(-2)).join('');
                return { encryptedCVV, key: Array.from(key).map(byte => ('0' + byte.toString(16)).slice(-2)).join('') };
            });
    }
});*/
