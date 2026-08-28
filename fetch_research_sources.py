import re, sys, time
from pathlib import Path
import requests
from bs4 import BeautifulSoup

URLS = [
('google-factory-images','https://developers.google.com/android/images'),
('google-full-ota','https://developers.google.com/android/ota'),
('avb-device-state','https://source.android.com/docs/security/features/verifiedboot/device-state'),
('avb-rollback','https://source.android.com/docs/security/features/verifiedboot/verified-boot'),
('ab-updates','https://source.android.com/docs/core/ota/ab'),
('amapi-provision','https://developers.google.com/android/management/provision-device'),
('amapi-dedicated-policy','https://developers.google.com/android/management/policies/dedicated-devices'),
('lock-task','https://developer.android.com/work/dpc/dedicated-devices/lock-task-mode'),
('amapi-command','https://developers.google.com/android/management/reference/rest/v1/enterprises.devices/issueCommand'),
('amapi-feedback','https://developers.google.com/android/management/app-feedback'),
('android-auto-backup','https://developer.android.com/identity/data/autobackup'),
('android-keystore','https://developer.android.com/privacy-and-security/keystore'),
('file-based-encryption','https://source.android.com/docs/security/features/encryption/file-based'),
('logcat','https://developer.android.com/tools/logcat'),
('bugreports','https://source.android.com/docs/core/tests/debug/read-bug-reports'),
('pixel-force-restart','https://support.google.com/pixelphone/answer/7374159?hl=en'),
('pixel6a-battery','https://support.google.com/pixelphone/answer/16340779?hl=en'),
('pixel-repair','https://pixelrepair.withgoogle.com/'),
('pixel-updates','https://support.google.com/pixelphone/answer/4457705?hl=en'),
('play-integrity','https://developer.android.com/google/play/integrity/verdicts'),
('graphene-install','https://grapheneos.org/install/web'),
('graphene-faq','https://grapheneos.org/faq'),
('uhubctl','https://github.com/mvp/uhubctl'),
('ykush','https://www.yepkit.com/products/ykush'),
('age','https://github.com/FiloSottile/age'),
]

def clean(html):
    s=BeautifulSoup(html,'html.parser')
    for tag in s(['script','style','noscript','svg','nav','footer']): tag.decompose()
    main=s.find('main') or s.find('article') or s.body or s
    txt=main.get_text('\n',strip=True)
    txt=re.sub(r'\n{3,}','\n\n',txt)
    return txt

out=Path('research_sources'); out.mkdir(exist_ok=True)
rows=[]
for slug,url in URLS:
    try:
        r=requests.get(url,timeout=45,headers={'User-Agent':'Mozilla/5.0 research/1.0'})
        txt=clean(r.text)
        (out/f'{slug}.txt').write_text(f'URL: {r.url}\nSTATUS: {r.status_code}\n\n{txt}',encoding='utf-8')
        rows.append((slug,r.status_code,len(txt),r.url))
    except Exception as e:
        rows.append((slug,'ERR',0,str(e)))
    time.sleep(.15)
print('\n'.join('\t'.join(map(str,x)) for x in rows))
