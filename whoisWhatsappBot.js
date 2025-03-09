require("dotenv").config();
const whois = require("whois");
const schedule = require("node-schedule");
const { default: makeWASocket, useMultiFileAuthState } = require("@whiskeysockets/baileys");
const qrcode = require("qrcode-terminal");
const axios = require("axios"); // Add axios for RDAP API calls

// Global socket reference and connection state
let sock = null;
let isConnected = false;
let qrDisplayed = false;
let qrTimeout = null;
const QR_MAX_RETRY = 3; // Maximum number of QR code generations
let qrRetryCount = 0;
const QR_TIMEOUT_SECONDS = 60; // Seconds to wait for QR code scan

// Start WhatsApp connection
async function startWhatsApp() {
  const { state, saveCreds } = await useMultiFileAuthState("auth_info_baileys");
  
  // Clear any existing QR timeout
  if (qrTimeout) {
    clearTimeout(qrTimeout);
    qrTimeout = null;
  }
  
  // Reset QR display status
  qrDisplayed = false;
  
  sock = makeWASocket({
    auth: state,
    printQRInTerminal: false, // We'll handle QR code display manually
    connectTimeoutMs: 60000, // Increase connection timeout to 60 seconds
    waitForChats: true, // Wait for chats to be loaded
  });

  sock.ev.on("creds.update", saveCreds);
  
  // Create a promise that resolves when connection is successful
  return new Promise((resolve, reject) => {
    // Connection events for debugging
    sock.ev.on("connection.update", (update) => {
      const { connection, lastDisconnect, qr } = update || {};
      
      if (qr && !qrDisplayed && qrRetryCount < QR_MAX_RETRY) {
        // Display QR and set timeout
        qrDisplayed = true;
        qrRetryCount++;
        console.log("\n\n============= WHATSAPP QR CODE =============");
        console.log(`QR CODE ATTEMPT ${qrRetryCount}/${QR_MAX_RETRY} - SCAN WITHIN ${QR_TIMEOUT_SECONDS} SECONDS`);
        console.log("Scan this QR code with YOUR WhatsApp account:");
        console.log("This will connect the bot to your WhatsApp account");
        console.log("and allow it to send messages on your behalf.");
        console.log("(Similar to logging into WhatsApp Web)");
        qrcode.generate(qr, { small: true });
        console.log("============================================\n\n");
        
        // Set timeout for QR code
        qrTimeout = setTimeout(() => {
          console.log("\n⌛ QR code timed out. Generating new QR code...");
          qrDisplayed = false;
          // No need to call startWhatsApp - the connection.update will fire again with a new QR
        }, QR_TIMEOUT_SECONDS * 1000);
      }
      
      if(connection === "close") {
        console.log("WhatsApp connection closed. Reconnecting...");
        isConnected = false;
        
        // Clean up the QR timeout if it exists
        if (qrTimeout) {
          clearTimeout(qrTimeout);
          qrTimeout = null;
        }
        
        // Check if the connection was closed due to logout or some unrecoverable error
        const statusCode = lastDisconnect?.error?.output?.statusCode;
        if (statusCode !== 401 && statusCode !== 408) { // Not logout or timeout
          // Attempt to reconnect
          setTimeout(() => {
            console.log("Attempting to reconnect...");
            // Reset QR counter on reconnect attempt
            if (qrRetryCount >= QR_MAX_RETRY) {
              qrRetryCount = 0;
              console.log("QR code attempt counter reset.");
            }
            startWhatsApp().then(resolve).catch(reject);
          }, 5000); // Wait 5 seconds before reconnecting
        } else {
          reject(new Error(`Connection closed with status code: ${statusCode}`));
        }
      } else if(connection === "open") {
        console.log("WhatsApp connection successful!");
        // Clear QR timeout if exists
        if (qrTimeout) {
          clearTimeout(qrTimeout);
          qrTimeout = null;
        }
        
        // Reset QR counter on successful connection
        qrRetryCount = 0;
        isConnected = true;
        resolve(sock);
      }
    });
    
    // Also listen for message upsert as another indicator of successful connection
    sock.ev.on("messages.upsert", () => {
      if (!isConnected) {
        console.log("Message received, connection active");
        isConnected = true;
        resolve(sock);
      }
    });
    
    // Add a global timeout for the entire connection process
    setTimeout(() => {
      if (!isConnected) {
        console.log("⛔ WhatsApp connection timed out!");
        if (qrRetryCount >= QR_MAX_RETRY) {
          console.log("❌ Maximum QR code attempts reached. Please restart the bot.");
          reject(new Error("Maximum QR code attempts reached"));
        }
      }
    }, QR_MAX_RETRY * QR_TIMEOUT_SECONDS * 1000 + 10000); // Total time + buffer
  });
}

// Enhanced WHOIS query function - with RDAP fallback
async function checkDomainExpiration(domain) {
  try {
    // First try WHOIS
    const expiryDate = await checkWithWhois(domain);
    if (expiryDate) return expiryDate;
    
    // If WHOIS failed or rate limited, try RDAP as fallback
    console.log("WHOIS failed, trying RDAP instead...");
    return await checkWithRdap(domain);
  } catch (error) {
    throw error;
  }
}

// WHOIS lookup implementation
function checkWithWhois(domain) {
  return new Promise((resolve, reject) => {
    whois.lookup(domain, (err, data) => {
      if (err) return reject(err);
      
      // Check for rate limiting
      if (data && data.includes("Rate limit exceeded")) {
        console.log("WHOIS rate limit exceeded, will try RDAP");
        return resolve(null);
      }
      
      // Different formats of expiration date in WHOIS data
      const expiryPatterns = [
        /Expiration Date:\s*(.+)/i,
        /Registry Expiry Date:\s*(.+)/i,
        /Registrar Registration Expiration Date:\s*(.+)/i,
        /Domain Expiration Date:\s*(.+)/i,
        /Expires on:\s*(.+)/i,
        /Expiry date:\s*(.+)/i
      ];
      
      let expiryDate = null;
      
      for (const pattern of expiryPatterns) {
        const match = data.match(pattern);
        if (match) {
          try {
            expiryDate = new Date(match[1].trim());
            if (!isNaN(expiryDate.getTime())) {
              break;
            }
          } catch (e) {
            console.log(`Date conversion error: ${e.message}`);
          }
        }
      }
      
      if (expiryDate) {
        resolve(expiryDate);
      } else {
        console.log("WHOIS response:", data); // Log full response for debugging
        resolve(null); // Return null instead of rejecting
      }
    });
  });
}

// RDAP lookup implementation
async function checkWithRdap(domain) {
  try {
    // Extract TLD to determine which RDAP server to use
    const tld = domain.split('.').pop();
    
    // First try direct RDAP lookup for the domain
    const rdapUrl = `https://rdap.org/domain/${domain}`;
    console.log(`Trying RDAP lookup at: ${rdapUrl}`);
    
    const response = await axios.get(rdapUrl, { timeout: 10000 });
    
    if (response.data && response.data.events) {
      // Look for expiration event in RDAP data
      const expirationEvent = response.data.events.find(
        event => event.eventAction === "expiration" || 
                event.eventAction === "registrationExpiration"
      );
      
      if (expirationEvent && expirationEvent.eventDate) {
        const expiryDate = new Date(expirationEvent.eventDate);
        if (!isNaN(expiryDate.getTime())) {
          return expiryDate;
        }
      }
    }
    
    throw new Error("RDAP response did not contain expiration information");
  } catch (error) {
    console.error("RDAP error:", error.message);
    throw new Error(`Domain expiration date couldn't be retrieved: ${error.message}`);
  }
}

// Function to ensure WhatsApp connection is active
async function ensureWhatsAppConnection(maxRetries = 3) {
  let retries = 0;
  
  while (retries < maxRetries) {
    if (isConnected && sock && sock.user) {
      return true;
    }
    
    console.log(`Checking WhatsApp connection (${retries + 1}/${maxRetries})...`);
    
    // If no connection, try to reconnect
    if (!sock || !isConnected) {
      console.log("No connection, restarting...");
      sock = await startWhatsApp();
      await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10 seconds
    }
    
    retries++;
  }
  
  return isConnected && sock && sock.user;
}

// Modify the sendWhatsAppMessage function to handle undefined recipient
async function sendWhatsAppMessage(message) {
  try {
    // Make sure the client is connected before attempting to send messages
    const connectionOk = await ensureWhatsAppConnection();
    
    if (!connectionOk) {
      console.log('❌ WhatsApp client connection could not be established after multiple retries.');
      return null;
    }
    
    // Make sure recipient is properly defined
    const recipient = process.env.RECIPIENT_NUMBER;
    
    if (!recipient) {
      console.log('❌ No recipient number defined in environment variables.');
      return null;
    }
    
    // Ensure recipient is in the proper format (add @s.whatsapp.net if not already there)
    const jid = recipient.includes('@s.whatsapp.net') ? 
      recipient : `${recipient}@s.whatsapp.net`;
    
    console.log(`📤 Sending message to: ${jid}`);
    
    const result = await sock.sendMessage(jid, { text: message });
    console.log('✅ WhatsApp message sent successfully!');
    return result;
  } catch (error) {
    console.log(`❌ WhatsApp message sending error: ${error}`);
    // Don't throw error to prevent bot from crashing
    return null;
  }
}

// Daily WHOIS check and test function
async function startBot() {
  console.log("🤖 Starting WhatsApp and WHOIS bot...");
  
  try {
    // Initialize WhatsApp and wait for successful connection
    console.log("Starting WhatsApp connection...");
    console.log("⚠️ Notice: You may need to scan a WhatsApp QR code, please monitor the terminal screen.");
    
    sock = await startWhatsApp();
    
    console.log("⏳ Waiting for connection to be fully established...");
    // Wait additional time to ensure connection is fully established
    await new Promise(resolve => setTimeout(resolve, 15000));
    
    if (!isConnected || !sock || !sock.user) {
      console.log("⚠️ WhatsApp connection not fully established. Retrying...");
      await ensureWhatsAppConnection();
    }
    
    // Check if we're connected after all attempts
    if (!isConnected || !sock || !sock.user) {
      throw new Error("WhatsApp connection failed! Please restart the bot and scan the QR code.");
    }
    
    // Define domain to check after connection is established
    const DOMAIN = process.env.CHECK_DOMAIN;
    
    if (!DOMAIN) {
      throw new Error("No domain specified in environment variables. Please set CHECK_DOMAIN in .env file.");
    }
    
    // Rest of the function continues as before
    console.log(`🔍 Initial test: Checking domain ${DOMAIN}...`);
    try {
      const expireDate = await checkDomainExpiration(DOMAIN);
      console.log(`📅 Expiration Date: ${expireDate}`);
      
      const now = new Date();
      const daysUntilExpiry = Math.floor((expireDate - now) / (1000 * 60 * 60 * 24));
      
      if (expireDate < now) {
        const alertMessage = `🚨 ATTENTION! ${DOMAIN} appears to have expired! Check immediately!`;
        console.log(alertMessage);
        await sendWhatsAppMessage(alertMessage);
      } else if (daysUntilExpiry <= 30) {
        const alertMessage = `⚠️ Warning: Domain ${DOMAIN} will expire in ${daysUntilExpiry} days!`;
        console.log(alertMessage);
        await sendWhatsAppMessage(alertMessage);
      } else {
        const infoMessage = `ℹ️ Domain ${DOMAIN} will expire in ${daysUntilExpiry} days.`;
        console.log(infoMessage);
        await sendWhatsAppMessage(infoMessage);
      }
    } catch (error) {
      console.error("❌ Initial test error:", error);
      await sendWhatsAppMessage(`Whois Bot Error: ${error.message || error}`);
    }
  } catch (error) {
    console.error("❌ Bot startup error:", error);
  }

  // Schedule a task that runs at 9 AM every day
  schedule.scheduleJob("0 9 * * *", async () => {
    const DOMAIN = process.env.CHECK_DOMAIN;
    if (!DOMAIN) {
      console.error("❌ No domain specified in environment variables.");
      return;
    }

    console.log(`🔍 Running daily WHOIS query for ${DOMAIN}...`);

    try {
      const expireDate = await checkDomainExpiration(DOMAIN);
      console.log(`📅 Expiration Date: ${expireDate}`);

      const now = new Date();
      const daysUntilExpiry = Math.floor((expireDate - now) / (1000 * 60 * 60 * 24));
      
      if (expireDate < now) {
        const alertMessage = `🚨 ATTENTION! ${DOMAIN} appears to have expired! Check immediately!`;
        console.log(alertMessage);
        await sendWhatsAppMessage(alertMessage);
      } else if (daysUntilExpiry <= 30) {
        const alertMessage = `⚠️ Warning: Domain ${DOMAIN} will expire in ${daysUntilExpiry} days!`;
        console.log(alertMessage);
        await sendWhatsAppMessage(alertMessage);
      }
    } catch (error) {
      console.error("❌ Error:", error);
      await sendWhatsAppMessage(`Whois Bot Error: ${error}`);
    }
  });

  console.log("✅ Whois tracking bot is running...");
}

// Start the bot
startBot().catch(error => {
  console.error("❌ Bot startup error:", error);
});
