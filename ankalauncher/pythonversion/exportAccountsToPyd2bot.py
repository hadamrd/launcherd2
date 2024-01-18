from ankalauncher.pythonversion.CryptoHelper import CryptoHelper
from pyd2bot.logic.managers.AccountManager import AccountManager

apikeys = CryptoHelper.get_all_stored_apikeys()
certs = CryptoHelper.get_all_stored_certificates()

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
    try:
        account_data = AccountManager.fetch_account(1, apikey, certid, certhash)
    except Exception as e:
        print(f"Failed to fetch account for reason: {e}")
        continue
    print(account_data)