import json
import os
import time
import logging
import ldap3
from ldap3 import Server, Connection, ALL, NTLM
from email.mime.text import MIMEText
import smtplib
import string
import secrets

# Charger la configuration depuis un fichier JSON
with open('config.json') as f:
    config = json.load(f)

# Configuration du logging
logging.basicConfig(
    filename=config['log']['file'],
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_ldap_connection():
    """Établit une connexion LDAP sécurisée en utilisant les informations d'identification fournies."""
    server = Server(config['ldap']['server'], use_ssl=True, get_info=ALL)

    logging.info(f"Connecting to LDAP server: {config['ldap']['server']}")
    logging.info(f"Using username: {config['ldap']['username']}")

    try:
        conn = Connection(server,
                          user=config['ldap']['username'],
                          password=config['ldap']['password'],
                          authentication=NTLM)
        if not conn.bind():
            logging.error(f"Unable to connect to LDAP server. Bind result: {conn.result}")
            return None
        logging.info("Successfully connected to LDAP server.")
        return conn
    except Exception as e:
        logging.error(f"Error connecting to LDAP server: {e}")
        return None

def is_user_admin(conn, user_dn):
    """Vérifie si un utilisateur est un administrateur."""
    conn.search(config['ldap']['search_base'], f'(member={user_dn})', attributes=['cn'])
    if conn.entries:
        for entry in conn.entries:
            if 'admin' in entry.cn.lower():
                return True
    return False

def is_user_in_vip_group(conn, user_dn):
    """Vérifie si un utilisateur appartient au groupe VIP."""
    conn.search(config['ldap']['search_base'], f'(member={user_dn})', attributes=['cn'])
    if conn.entries:
        for entry in conn.entries:
            if entry.dn.lower() == config['ldap']['vipGroup'].lower():
                return True
    return False

def process_json_file(file_path):
    """Traite un fichier JSON pour réinitialiser le mot de passe."""
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
    except Exception as e:
        logging.error(f"Error reading JSON file {file_path}: {e}")
        return

    conn = get_ldap_connection()
    if not conn:
        return

    user_dn = f"CN={data['user_samAccountName']},{config['ldap']['search_base']}"

    # Vérifier si l'utilisateur est un administrateur ou dans le groupe VIP
    if is_user_admin(conn, user_dn):
        logging.info(f"User {data['user_samAccountName']} is an admin. Skipping password reset.")
        return

    if is_user_in_vip_group(conn, user_dn):
        logging.info(f"User {data['user_samAccountName']} is in VIP group. Skipping password reset.")
        return

    new_password = generate_password(data['user_samAccountName'])

    if config['debug_mode']:
        logging.info(f"DEBUG MODE: Simulating password reset for {data['user_samAccountName']}. New password would be: {new_password}")
    else:
        try:
            # Réinitialiser le mot de passe
            conn.extend.microsoft.modify_password(user_dn, new_password)

            if conn.result['result'] == 0:
                logging.info(f"Password successfully reset for {data['user_samAccountName']}")
                send_notification_email(data['user_samAccountName'], new_password, data['sponsor_email'])
                send_notification_email(data['user_samAccountName'], new_password, config['itServiceEmail'])
                move_processed_file(file_path)
                # Forcer le changement de mot de passe à la première connexion
                conn.modify(user_dn, {'pwdLastSet': (ldap3.MODIFY_REPLACE, [0])})
            else:
                logging.error(f"Failed to reset password for {data['user_samAccountName']}: {conn.result['description']}")
        except Exception as e:
            logging.error(f"Error resetting password: {e}")

def generate_password(username):
    """Génère un mot de passe sécurisé selon les spécifications."""
    length = 12
    all_characters = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"

    while True:
        password = ''.join(secrets.choice(all_characters) for _ in range(length))

        # Vérifier les caractéristiques du mot de passe
        if (any(c.islower() for c in password) +
            any(c.isupper() for c in password) +
            any(c.isdigit() for c in password) +
            any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password) >= 3 and
            username.lower() not in password.lower()):
            return password

def send_notification_email(username, new_password, recipient_email):
    """Envoie un e-mail de notification après la réinitialisation du mot de passe."""
    msg = MIMEText(f"The password for {username} has been reset to: {new_password}")
    msg['Subject'] = 'Password Reset Notification'
    msg['From'] = config['smtp']['fromAddress']
    msg['To'] = recipient_email

    try:
        logging.info(f"Connecting to SMTP server: {config['smtp']['server']}:{config['smtp']['port']}")
        server = smtplib.SMTP(config['smtp']['server'], config['smtp']['port'])
        server.set_debuglevel(1)  # Active le mode debug pour plus de détails
        server.starttls()
        logging.info(f"Sending email to: {recipient_email}")
        server.sendmail(msg['From'], [msg['To']], msg.as_string())
        logging.info("Notification email sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
    finally:
        server.quit()

def move_processed_file(file_path):
    """Déplace le fichier traité vers un répertoire de sauvegarde."""
    processed_dir = config['processed']['path']
    os.makedirs(processed_dir, exist_ok=True)
    os.rename(file_path, os.path.join(processed_dir, os.path.basename(file_path)))

def main():
    """Boucle principale du service."""
    json_dir = config['share']['path']

    while True:
        for filename in os.listdir(json_dir):
            if filename.endswith('.json'):
                file_path = os.path.join(json_dir, filename)
                process_json_file(file_path)

        time.sleep(config['scan_interval'])  # Attendre selon l'intervalle défini dans le fichier de configuration

if __name__ == '__main__':
    main()
