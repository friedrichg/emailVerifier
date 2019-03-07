from flask import redirect
from flask import Response
from os import environ as osenviron
from json import loads as jsonloads
from json import dumps as jsondumps
from base64 import b64encode
from gzip import compress as gzipcompress 
from urllib.parse import quote as urllibparsequote
from re import compile as recompile
from functools import wraps as functoolswraps
from random import random 
from requests import get as requestsget

authKey='authorization'
if "ENVIRONMENT" in osenviron and osenviron["ENVIRONMENT"] == "development":
    authurl = 'http://localhost:5000/auth'
    rooturl = "http://localhost:5000"
    validateurl = 'http://localhost:5000/validate'
else:
    authurl = 'https://europe-west1-emailverifier-218311.cloudfunctions.net/emailVerifierAuth'
    rooturl = 'https://europe-west1-emailverifier-218311.cloudfunctions.net/emailVerifierRoot'
    validateurl = 'https://europe-west1-emailverifier-218311.cloudfunctions.net/emailVerifierValidate'
remail=recompile(r"[^\s@,;]*@[^\s@,;]+")
apiurl = 'https://apilayer.net/api/check?access_key={key}&email={email}&smtp=1'
key = 'a066007485b5fb534657daa24bdff746'
mockresponse = """{{
  "email":"{email}",
  "did_you_mean":"{did_you_mean}",
  "user":"{user}",
  "domain":"{domain}",
  "format_valid":{format_valid},
  "mx_found":{mx_found},
  "smtp_check":{smtp_check},
  "catch_all":{catch_all},
  "role":{role},
  "disposable":{disposable},
  "free":{free},
  "score": {score},
  "mocked": true
}}"""

def authRequired(func):
    """Make sure user is logged in before proceeding"""
    @functoolswraps(func)
    def wrapper_login_required(request):
        recAuth=request.cookies.get("authKey")
        if recAuth != authKey:
            return Response(f'Acceso denegado. Ingrese <a href="{authurl}">aqu&iacute;</a>',401)
        return func(request)
    return wrapper_login_required

def randomBoolean():
    if random()> 0.5:
        return "true"
    else:
        return "false"

def validateExternal(email):
    response = requestsget(apiurl.format(key=key,email=email))
    if response.status_code != 200:
        return None,"{}: Status invalido. Contacte al administrador".format(response.status_code)
    return response.json(), None

def validateMock(email):
    parts = email.split("@")
    return jsonloads(mockresponse.format(
        email=email,
        did_you_mean="sugerencia-"+email,
        user=parts[0],
        domain=parts[1],
        format_valid=randomBoolean(),
        mx_found=randomBoolean(),
        smtp_check=randomBoolean(),
        catch_all=randomBoolean(),
        role=randomBoolean(),
        free=randomBoolean(),
        disposable=randomBoolean(),
        score=random(),
        )), None

@authRequired
def emailVerifierValidate(request):
    """Responds to any HTTP request.
    Args:
        request (flask.Request): HTTP request object.
    Returns:
        The response text or any set of values that can be turned into a
        Response object using
        `make_response <http://flask.pocoo.org/docs/0.12/api/#flask.Flask.make_response>`.
    """
    emails = ""
    cleanedup = ""
    details = ""
    errors = ""
    if request.form and 'emails' in request.form and request.form['emails']:
        emails = request.form['emails']
        emailsl = remail.findall(emails)
        detailsl = []
        cleanedupl = []
        errorsl = []
        mock=request.cookies.get("mock") != "false"

        for i in range(len(emailsl)):
            if mock:
                detail, err = validateMock(emailsl[i])
            else:
                detail, err = validateExternal(emailsl[i])
            print("detail {}".format(detail))
            if err:
                errorsl.append(err)
                continue
            detail["score"] = detail["score"] * 100
            if detail["score"] > 64:
                detail["color"] = "success"
                cleanedupl.append(detail["email"])
            elif detail["score"] > 32:
                detail["color"] = "warning"
            else:
                detail["color"] = "danger"
            detailsl.append(detail)
        cleanedup = b64encode(gzipcompress(",".join(cleanedupl).encode()))
        details = b64encode(gzipcompress(jsondumps(detailsl).encode()))
        emails = b64encode(gzipcompress(emails.encode()))
        errors = b64encode(gzipcompress(",".join(errorsl).encode()))
    return redirect("{}?emails={}&cleanedup={}&details={}&errors={}".format(
        rooturl,
        urllibparsequote(emails),
        urllibparsequote(cleanedup),
        urllibparsequote(details),
        urllibparsequote(errors)
        ))

