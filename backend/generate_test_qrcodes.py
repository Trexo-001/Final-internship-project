import qrcode
import os

test_urls = {
    "legit_wikipedia": "https://www.wikipedia.org",
    "legit_github": "https://github.com/torvalds/linux",
    "legit_mdn": "https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API",
    "phishing_paypal": "http://paypal-secure-login.verify-account.tk",
    "phishing_ip": "http://192.168.1.105/login.php?session=expired",
    "phishing_amazon": "https://amaz0n-account-update.xyz/confirm",
    "phishing_facebook": "http://facebook.com-security-check.ml/login",
}

os.makedirs("test_qrcodes", exist_ok=True)

for name, url in test_urls.items():
    img = qrcode.make(url)
    path = f"test_qrcodes/{name}.png"
    img.save(path)
    print(f"Created: {path}  ->  {url}")