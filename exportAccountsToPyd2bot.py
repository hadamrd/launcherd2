from pyd2bot.logic.managers.AccountManager import AccountManager
import json
apikeys_file = "apikeys.json"
certs_file = "certs.json"

with open(apikeys_file) as f:
    apikeys = json.load(f)

with open(certs_file) as f:
    certs = json.load(f)

discovered_accounts = []
for apikey_details in apikeys:
    keydata = apikey_details['apikey']
    apikey = keydata['key']
    certid = ""
    certhash = ""
    if 'certificate' in keydata:
        certid = keydata['certificate']['id']
        for cert in certs:
            certdata = cert['cert']
            if certdata['id'] == certid:
                certhash = cert['hash']
                break
    
    account_data = AccountManager.fetch_account(1, apikey, certid, certhash)
    print(account_data)