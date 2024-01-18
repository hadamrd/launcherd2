import json

from ankalauncher.pythonversion.CryptoHelper import CryptoHelper

from pyd2bot.logic.managers.AccountManager import AccountManager

apikeys = CryptoHelper.get_all_stored_apikeys()
certs = CryptoHelper.get_all_stored_certificates()

with open("accounts.json", "w") as f:
    json.dump(apikeys, f, indent=4)
    
with open("certs.json", "w") as f:
    json.dump(certs, f, indent=4)