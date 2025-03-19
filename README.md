# not working anymore


## Domain Checker WhatsApp Bot

A WhatsApp bot that checks domain expiration dates and sends alerts.

### Installation

1. Clone this repository
2. Install dependencies:
   ```
   npm install
   ```
3. Create a `.env` file with your configuration:
   ```
   MY_WHATSAPP=905XXXXXXXXX
   CHECK_DOMAIN=example.com
   ```
4. Run the bot:
   ```
   npm start
   ```

### Features

- Checks domain expiration dates using WHOIS
- Sends alerts via WhatsApp when domains are about to expire
- Scheduled daily checks
- Immediate check on startup

### Notes

- The first time you run the bot, you'll need to scan a QR code with your WhatsApp to authenticate
- Make sure your WhatsApp number is formatted with country code, without '+' (e.g., 905XXXXXXXXX)
