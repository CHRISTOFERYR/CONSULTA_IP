from flask import Flask, request, render_template
import re

app = Flask(__name__)

def is_ip(input_str):
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return ip_pattern.match(input_str) is not None

def get_virustotal_url(input_str):
    if is_ip(input_str):
        return f"https://www.virustotal.com/gui/ip-address/{input_str}"
    else:
        return f"https://www.virustotal.com/gui/url/{input_str}"

def get_abuseipdb_url(ip):
    return f"https://www.abuseipdb.com/check/{ip}"

def get_ibm_xforce_url(input_str):
    if is_ip(input_str):
        return f"https://exchange.xforce.ibmcloud.com/ip/{input_str}"
    else:
        return f"https://exchange.xforce.ibmcloud.com/url/{input_str}"

def get_brightcloud_url(ip):
    return f"https://www.brightcloud.com/tools/ip-lookup.php?ip={ip}"

def get_mxtoolbox_url(input_str):
    if is_ip(input_str):
        return f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3A{input_str}"
    else:
        return f"https://mxtoolbox.com/SuperTool.aspx?action=url%3A{input_str}"

def get_cisco_talos_url(input_str):
    return f"https://talosintelligence.com/reputation_center/lookup?search={input_str}"

def get_metadefender_url(input_str):
    if is_ip(input_str):
        return f"https://metadefender.opswat.com/?ip={input_str}"
    else:
        return f"https://metadefender.opswat.com/?url={input_str}"

def get_multirbl_url(ip):
    return f"https://multirbl.valli.org/lookup/{ip}.html"

def get_symantec_url(ip):
    return f"https://sitereview.bluecoat.com/#/lookup-result/{ip}"

def get_alienvault_url(ip):
    return f"https://otx.alienvault.com/indicator/ip/{ip}"

def get_urlvoid_url(input_str):
    if is_ip(input_str):
        return f"https://www.urlvoid.com/ip/{input_str}"
    else:
        return f"https://www.urlvoid.com/url/{input_str}"

def get_sucuri_url(input_str):
    return f"https://sitecheck.sucuri.net/results/{input_str}"

def get_scamadviser_url(input_str):
    if is_ip(input_str):
        return f"https://www.scamadviser.com/check-website/{input_str}"
    else:
        return f"https://www.scamadviser.com/check-website/{input_str}"

def get_blacklistmaster_url(ip):
    return f"https://www.blacklistmaster.com/check/?ip={ip}"

def get_url2_url(ip):
    return f"https://www.url2png.com/"

def get_docguard_url(ip):
    return f"https://app.docguard.io/"

def get_criminal_ip_url(input_str):
    if is_ip(input_str):
        return f"https://www.criminalip.io/en/ip/{input_str}"
    else:
        return f"https://www.criminalip.io/en/url/{input_str}"

def get_ssllabs_url(input_str):
    return f"https://www.ssllabs.com/ssltest/analyze.html?d={input_str}"

def get_ipinfo_url(ip):
    return f"https://ipinfo.io/{ip}"

def get_maxmind_url(ip):
    return f"https://www.maxmind.com/en/geoip-demo"

def get_geotool_url(ip):
    return f"https://iplookup.flagfox.net/?ip={ip}"

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        input_str = request.form['input']
        urls = {
            "VirusTotal": get_virustotal_url(input_str),
            "AbuseIPDB": get_abuseipdb_url(input_str) if is_ip(input_str) else "N/A",
            "IBM X-Force Exchange": get_ibm_xforce_url(input_str),
            "BrightCloud": get_brightcloud_url(input_str) if is_ip(input_str) else "N/A",
            "MxToolbox": get_mxtoolbox_url(input_str),
            "Cisco Talos": get_cisco_talos_url(input_str),
            "MetaDefender": get_metadefender_url(input_str),
            "MultiRBL": get_multirbl_url(input_str) if is_ip(input_str) else "N/A",
            "Symantec": get_symantec_url(input_str) if is_ip(input_str) else "N/A",
            "AlienVault": get_alienvault_url(input_str) if is_ip(input_str) else "N/A",
            "URLVoid": get_urlvoid_url(input_str),
            "Sucuri": get_sucuri_url(input_str),
            "Scamadviser": get_scamadviser_url(input_str),
            "BlacklistMaster": get_blacklistmaster_url(input_str) if is_ip(input_str) else "N/A",
            "URL2": get_url2_url(input_str),
            "DocGuard": get_docguard_url(input_str),
            "Criminal ip": get_criminal_ip_url(input_str),
            "SSL Labs": get_ssllabs_url(input_str),
            "IP info": get_ipinfo_url(input_str) if is_ip(input_str) else "N/A",
            "Max Mind": get_maxmind_url(input_str) if is_ip(input_str) else "N/A",
            "GeoTool": get_geotool_url(input_str) if is_ip(input_str) else "N/A"
        }
        return render_template('results.html', input_str=input_str, urls=urls)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)