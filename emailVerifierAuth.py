from flask import redirect

from os import environ as osenviron

authKey='authorization'
if "ENVIRONMENT" in osenviron and osenviron["ENVIRONMENT"] == "development":
    authurl = 'http://localhost:5000/auth'
    rooturl = "http://localhost:5000"
    validateurl = 'http://localhost:5000/validate'
else:
    authurl = 'https://europe-west1-emailverifier-218311.cloudfunctions.net/emailVerifierAuth'
    rooturl = 'https://europe-west1-emailverifier-218311.cloudfunctions.net/emailVerifierRoot'
    validateurl = 'https://europe-west1-emailverifier-218311.cloudfunctions.net/emailVerifierValidate'

def emailVerifierAuth(request):
    resp=redirect(rooturl)
    resp.set_cookie("authKey",authKey)
    if "mock" in request.args:
        resp.set_cookie("mock",request.args["mock"])
    else:
        resp.set_cookie("mock","true")
    return resp

