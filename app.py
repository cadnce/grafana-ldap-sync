#!/bin/env python
import random
import requests
import ldap
import string
#import logging

#logging.basicConfig()
#logging.getLogger().setLevel(logging.DEBUG)
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(logging.DEBUG)
#requests_log.propagate = True

grafana_base_name="http://localhost:3000/api"
auth = ("admin", "admin")
def get_ldap_user_list(group='ou=scientists'):
	con = ldap.initialize('ldap://ldap.forumsys.com:389')
	return con.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, "(ou=chemists)")[0][1]['uniqueMember']
	
def get_users_from_grafana():
	#curl 'http://localhost:3000/api/users' -XGET -u admin -H "Content-Type: application/json"
	res = requests.get("/".join((grafana_base_name, "users")), auth=auth)
	res.raise_for_status()
	# Json should look like
	#[{u'email': u'admin@localhost', u'login': u'admin', u'isAdmin': True, u'id': 1, u'name': u''}, {u'email': u'user@graf.com', u'login': u'user', u'isAdmin': True, u'id': 3, u'name': u'User'}]
	return { user['login']: user for user in res.json()}

def gen_password(len=30):
	return "".join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(len))

def make_user(username):
# curl -H "Content-Type: application/json" -XPOST -u admin  http://localhost:3000/api/admin/users -d '{"name":"User","email":"user@graf.com","login":"user","password":"userpassword" }
	user = {"login": username, "email": "{0}@example.com".format(username), "password": gen_password()} 
	
	res = requests.post("/".join((grafana_base_name, 'admin/users')), auth=auth, headers={"Content-Type": "application/json"}, json=user) 
	res.raise_for_status()

	return res.json()['id']

def make_admin(user_id):
	#curl 'http://localhost:3000/api/admin/users/3/permissions' -XPUT -H 'Content-Type: application/json' -u admin  -d '{"isGrafanaAdmin":true}'
	res = requests.put("/".join((grafana_base_name, "admin/users/{0}/permissions".format(user_id))), json={"isGrafanaAdmin": True}, auth=auth, headers={"Content-Type": "application/json"})
	print res.json()
	res.raise_for_status()


def create_user_or_make_admin(user):
	if user not in grafana_users:
		uid = make_user(user)
	else:
		uid = grafana_users[user]['id']
	make_admin(uid)

grafana_users = get_users_from_grafana()

for user_dn in get_ldap_user_list():
	username = user_dn.split(",")[0].split("=")[1]
	create_user_or_make_admin(username)