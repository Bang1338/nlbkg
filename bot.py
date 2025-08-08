import bcrypt
from cryptography.fernet import Fernet
import base64
import telebot
import threading
import time
import logging
from datetime import datetime
import secrets
import hashlib
from flask import Flask, request, render_template_string, redirect, url_for
import os

class SecureTelegramBot:
    def __init__(self):
        self.bot = None
        self.token = None
        self.authorized_users = [5990126462]
        self.setup_logging()
        self.bot_started = False
        self.flask_app = Flask(__name__)
        self.setup_flask_routes()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(message)s',
            handlers=[
                logging.FileHandler('bot_activity.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def get_chat_info(self, message):
        """Get chat type and format chat info for logging"""
        if message.chat.type == 'private':
            return f"PM[{message.chat.id}]"
        else:
            chat_tag = ""
            if hasattr(message.chat, 'username') and message.chat.username:
                chat_tag = f"-@{message.chat.username}"
            elif hasattr(message.chat, 'title') and message.chat.title:
                title = message.chat.title.replace('[', '').replace(']', '').replace('\n', ' ')[:30]
                chat_tag = f"-{title}"
            
            return f"G[{message.chat.id}{chat_tag}]"
    
    def log_user_activity(self, message, command_input):
        """Log user activity in the specified format"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        username = message.from_user.username if message.from_user.username else "NoUsername"
        user_id = message.from_user.id
        chat_info = self.get_chat_info(message)
        
        log_entry = f"[{timestamp}] {user_id}\t @{username}\t {chat_info}\t {command_input}"
        self.logger.info(log_entry)
    
    def is_authorized(self, user_id):
        """Check if user is authorized to use admin commands"""
        return user_id in self.authorized_users
    
    def decrypt_token(self, encrypted_token_b64, salt_b64, password):
        try:
            # Decode salt and encrypted token
            salt = base64.b64decode(salt_b64.encode())
            encrypted_token = base64.b64decode(encrypted_token_b64.encode())
            
            # Generate key from password
            key = bcrypt.kdf(
                password=password.encode('utf-8'),
                salt=salt,
                desired_key_bytes=32,
                rounds=100
            )
            
            # Decrypt token
            fernet = Fernet(base64.urlsafe_b64encode(key))
            decrypted_token = fernet.decrypt(encrypted_token).decode()
            
            return decrypted_token
            
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            return None
    
    def setup_flask_routes(self):
        """Setup Flask routes for password entry"""
        # Generate random URL path and secret
        self.secret_path = secrets.token_urlsafe(32)
        self.secret_hash = hashlib.sha3_512(secrets.token_urlsafe(64).encode()).hexdigest()
        
        # Store the expected secret parameter
        self.expected_secret = self.secret_hash
        
        # Print the access URL
        port = int(os.environ.get('PORT', 5000))
        render_url = os.environ.get('RENDER_EXTERNAL_URL', f'http://localhost:{port}')
        access_url = f"{render_url}/{self.secret_path}?s={self.secret_hash}"
        
        print("=" * 60)
        print("SECURE ACCESS URL:")
        print(access_url)
        print("=" * 60)
        print("Copy this URL and paste it in your browser to unlock the bot.")
        print("The URL will be destroyed after successful authentication.")
        
        @self.flask_app.route(f'/{self.secret_path}')
        def unlock_form():
            if self.bot_started:
                return "Bot is already running!", 200
                
            secret_param = request.args.get('s')
            if secret_param != self.expected_secret:
                return "Access denied!", 403
            
            return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Unlock Telegram Bot</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 50px; background: #f0f0f0; }
                    .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    input[type="password"] { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
                    button { width: 100%; padding: 12px; background: #0088cc; color: white; border: none; border-radius: 5px; cursor: pointer; }
                    button:hover { background: #0077bb; }
                    .error { color: red; margin: 10px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>🔐 Unlock Telegram Bot</h2>
                    <form method="post">
                        <input type="password" name="password" placeholder="Enter decryption password" required>
                        <button type="submit">Unlock Bot</button>
                    </form>
                </div>
            </body>
            </html>
            ''')
        
        @self.flask_app.route(f'/{self.secret_path}', methods=['POST'])
        def unlock_bot():
            if self.bot_started:
                return "Bot is already running!", 200
                
            password = request.form.get('password')
            if not password:
                return "Password required!", 400
            
            # Try to decrypt and start bot
            ENCRYPTED_TOKEN = "Z0FBQUFBQm9XQXRKTUZNSW9ON09yQml2Umx1M1JzdnhNTFhUZmNRUjlIdDlaVGlfOTFLQ1ZqMTdPMl9QcGpXd0RoVGM0Rm9Hd3JJWlFZdmkxMUNyUVM2NFNoQzB5RzRGMXBCSy1NSmpSQzczRGVNWmN3czNxM3A4NVFuVkUxbXRJOVhaTUIwTGplT28="  # Your encrypted token
            SALT = "JDJiJDEyJC82WlV2RVBhbVhkWDVZSjVhZDQ2U08="  # Your salt
            
            self.token = self.decrypt_token(ENCRYPTED_TOKEN, SALT, password)
            
            if not self.token:
                return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head><title>Error</title></head>
                <body style="font-family: Arial, sans-serif; margin: 50px; text-align: center;">
                    <h2 style="color: red;">❌ Invalid Password</h2>
                    <p>The password you entered is incorrect.</p>
                    <a href="javascript:history.back()">← Try Again</a>
                </body>
                </html>
                ''')
            
            # Start the Telegram bot in a separate thread
            try:
                self.bot = telebot.TeleBot(self.token)
                self.token = ""  # Clear token from memory
                self.bot.get_me()
                
                # Setup bot handlers
                self.setup_handlers()
                
                # Start bot in background thread
                bot_thread = threading.Thread(target=self.start_bot_polling)
                bot_thread.daemon = True
                bot_thread.start()
                
                self.bot_started = True
                
                # Destroy the route by removing it from Flask's URL map
                self.destroy_unlock_route()
                
                self.logger.info("Bot started successfully via web interface")
                
                return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head><title>Success</title></head>
                <body style="font-family: Arial, sans-serif; margin: 50px; text-align: center;">
                    <h2 style="color: green;">✅ Bot Unlocked Successfully!</h2>
                    <p>Your Telegram bot is now running 24/7.</p>
                    <p>This page is now destroyed for security.</p>
                </body>
                </html>
                ''')
                
            except Exception as e:
                self.logger.error(f"Failed to start bot: {e}")
                return f"Failed to start bot: {e}", 500
    
    def destroy_unlock_route(self):
        """Remove the unlock route from Flask for security"""
        try:
            # Remove the rule from Flask's URL map
            rules_to_remove = []
            for rule in self.flask_app.url_map.iter_rules():
                if f'/{self.secret_path}' in rule.rule:
                    rules_to_remove.append(rule)
            
            for rule in rules_to_remove:
                self.flask_app.url_map._rules.remove(rule)
                self.flask_app.url_map._rules_by_endpoint.pop(rule.endpoint, None)
            
            self.flask_app.url_map.update()
            print("🔒 Unlock route destroyed for security")
            
        except Exception as e:
            self.logger.error(f"Error destroying route: {e}")
    
    def start_bot_polling(self):
        """Start bot polling in a separate thread"""
        try:
            self.bot.polling(none_stop=True)
        except Exception as e:
            self.logger.error(f"Bot polling error: {e}")
    
    def setup_handlers(self):
        """Setup your Telegram bot handlers here"""
        @self.bot.message_handler(commands=['start'])
        def handle_start(message):
            self.log_user_activity(message, '/start')
            self.bot.reply_to(message, "Hello! I'm testing...")
        
    
    def run(self):
        """Run the Flask web server"""
        port = int(os.environ.get('PORT', 5000))
        self.flask_app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == "__main__":
    bot = SecureTelegramBot()
    bot.run()