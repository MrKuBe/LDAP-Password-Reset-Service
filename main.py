# Installation du service 
# python your_script.py install

# Démarrage du service 
#python your_script.py start

import json
import os
import time
import logging
import win32serviceutil
import win32service
import win32event
import servicemanager
import ldap3
from ldap3 import Server, Connection, ALL, NTLM
from email.mime.text import MIMEText
import smtplib
import string
import secrets
import win32security
import win32api

# Configuration du logging
logging.basicConfig(
    filename=config['log']['file'],
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Charger la configuration depuis un fichier JSON
with open('config.json') as f:
    config = json.load(f)

class PasswordResetService(win32serviceutil.ServiceFramework):
    _svc_name_ = "PasswordResetService"
    _svc_display_name_ = "Password Reset Service"
    _svc_description_ = "Service to reset passwords based on JSON requests."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.stop_requested = False

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.stop_requested = True

    def SvcDoRun(self):
        self.main()

    def get_ldap_connection(self):
        """Établit une connexion LDAP sécurisée en utilisant les informations d'identification du service Windows."""
        server = Server(config['ldap']['server'], use_ssl=True, get_info=ALL)

        # Récupérer le compte de service et le mot de passe à partir des informations d'identification du service
        ph = win32api.GetCurrentProcess()
        th = win32security.OpenProcessToken(ph, win32security.TOKEN_QUERY)
        sid_and_attrs = win32security.GetTokenInformation(th, win32security.TokenUser)
        sid = sid_and_attrs[0]
        user, domain, type_ = win32security.LookupAccountSid(None, sid)

        try:
            conn = Connection(server, user=f"{domain}\\{user}", password='', authentication=NTLM)
            if not conn.bind():
                logging.error("Unable to connect to LDAP server.")
                return None
            return conn
        except Exception as e:
            logging.error(f"Error connecting to LDAP server: {e}")
            return None

    def process_json_file(self, file_path):
        """Traite un fichier JSON pour réinitialiser le mot de passe."""
        try:
            with open(file_path, 'r') as file:
                data = json.load(file)
        except Exception as e:
            logging.error(f"Error reading JSON file {file_path}: {e}")
            return

        conn = self.get_ldap_connection()
        if not conn:
            return

        user_dn = f"CN={data['user_samAccountName']},{config['ldap']['user_base_dn']}"
        new_password = self.generate_password(data['user_samAccountName'])

        if config['debug_mode']:
            logging.info(f"DEBUG MODE: Simulating password reset for {data['user_samAccountName']}. New password would be: {new_password}")
        else:
            try:
                # Réinitialiser le mot de passe
                conn.extend.microsoft.modify_password(user_dn, new_password)

                if conn.result['result'] == 0:
                    logging.info(f"Password successfully reset for {data['user_samAccountName']}")
                    self.send_notification_email(data['user_samAccountName'], new_password)
                    self.move_processed_file(file_path)
                else:
                    logging.error(f"Failed to reset password for {data['user_samAccountName']}: {conn.result['description']}")
            except Exception as e:
                logging.error(f"Error resetting password: {e}")

    def generate_password(self, username):
        """Génère un mot de passe sécurisé selon les spécifications."""
        length = 12
        all_characters = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?/"

        while True:
            password = ''.join(secrets.choice(all_characters) for _ in range(length))

            # Vérifier les caractéristiques du mot de passe
            if (any(c.islower() for c in password) +
                any(c.isupper() for c in password) +
                any(c.isdigit() for c in password) +
                any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/" for c in password) >= 3 and
                username.lower() not in password.lower()):
                return password

    def send_notification_email(self, username, new_password):
        """Envoie un e-mail de notification après la réinitialisation du mot de passe."""
        msg = MIMEText(f"The password for {username} has been reset to: {new_password}")
        msg['Subject'] = 'Password Reset Notification'
        msg['From'] = config['smtp']['fromAddress']
        msg['To'] = config['itServiceEmail']

        try:
            server = smtplib.SMTP(config['smtp']['server'], config['smtp']['port'])
            server.starttls()
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
            logging.info("Notification email sent successfully.")
        except Exception as e:
            logging.error(f"Failed to send email: {e}")
        finally:
            server.quit()

    def move_processed_file(self, file_path):
        """Déplace le fichier traité vers un répertoire de sauvegarde."""
        processed_dir = config['processed']['path']
        os.makedirs(processed_dir, exist_ok=True)
        os.rename(file_path, os.path.join(processed_dir, os.path.basename(file_path)))

    def main(self):
        """Boucle principale du service."""
        json_dir = config['share']['path']

        while not self.stop_requested:
            for filename in os.listdir(json_dir):
                if filename.endswith('.json'):
                    file_path = os.path.join(json_dir, filename)
                    self.process_json_file(file_path)

            time.sleep(config['scan_interval'])  # Attendre selon l'intervalle défini dans le fichier de configuration

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(PasswordResetService)
