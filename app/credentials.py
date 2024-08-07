import os, json

CRED_DIR = 'credentials'

# handler for credentials provided as json files, instead of single string API keys
# secure handling is via 1pw loading the file into the environment of the individual process
# insecure handling is by storing the file in a credentials directory
def get_credential(name):
    cred = f'{name}_CREDENTIAL'
    if cred in os.environ:
        return json.loads(os.getenv(cred))
    
    cred_file = os.path.join(CRED_DIR, f'{cred}.json')
    if os.path.isfile(cred_file):
        with open(cred_file) as f:
            return json.load(f)
    else:
        raise FileNotFoundError(f'{cred} file is missing')
