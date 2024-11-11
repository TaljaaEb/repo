import requests

#auth
session = requests.Session()
session.auth = ('admin', 'admin$1234')

auth = session.post('http://' + '127.0.0.1')
response = session.get('http://' + hostname + ':8000/' + 'order-summary/') # any of [trolley, cart, checkout, ...]

#req = requests.get('http://127.0.0.1:8000/order-summary/')

#test_str = req.text

test_str_a = response.text

import re

def extract_strings_recursive(test_str, tag):
    # finding the index of the first occurrence of the opening tag
    start_idx = test_str.find("<" + tag + ">")
 
    # base case
    if start_idx == -1:
        return []
 
    # extracting the string between the opening and closing tags
    end_idx = test_str.find("</" + tag + ">", start_idx)
    res = [test_str[start_idx+len(tag)+2:end_idx]]
 
    # recursive call to extract strings after the current tag
    res += extract_strings_recursive(test_str[end_idx+len(tag)+3:], tag)
 
    return res

tag = "b"
lines = extract_strings_recursive(test_str, "ln")

for line in lines:
    print(line)
