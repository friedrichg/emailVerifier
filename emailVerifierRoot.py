
from flask import Response
from os import environ as osenviron
from json import loads as jsonloads

from base64 import b64decode
from gzip import decompress as gzipdecompress
from binascii import Error as binasciiError
from functools import wraps as functoolswraps
from zlib import error as zliberror




authKey='authorization'
if "ENVIRONMENT" in osenviron and osenviron["ENVIRONMENT"] == "development":
    authurl = 'http://localhost:5000/auth'
    rooturl = "http://localhost:5000"
    validateurl = 'http://localhost:5000/validate'
else:
    authurl = 'https://europe-west1-emailverifier-218311.cloudfunctions.net/emailVerifierAuth'
    rooturl = 'https://europe-west1-emailverifier-218311.cloudfunctions.net/emailVerifierRoot'
    validateurl = 'https://europe-west1-emailverifier-218311.cloudfunctions.net/emailVerifierValidate'

resultitem = """<a class="list-group-item list-group-item-action list-group-item-{color}" id="list-email{iter}-list" data-toggle="list" href="#list-email{iter}" role="tab" aria-controls="email{iter}">{email}</a>"""
resulttabitem = """
<div class="tab-pane fade" id="list-email{iter}" role="tabpanel" aria-labelledby="list-email{iter}-list">
  <table class="table">
  <tbody>
    <tr>
      <td scope="row" title="Confiabilidad: Mayor a 64 => Buena, Menor a 32 => Mala">Confiabilidad</td>
      <td>{score:.0f}%</td>
    </tr>
    <tr>
      <td scope="row" title="Devuelve el nombre de usuario asociado a la direcci&oacute;n de correo">User</td>
      <td>{user}</td>
    </tr>
    <tr>
      <td scope="row" title="Devuelve el dominio del correo">Dominio</td>
      <td>{domain}</td>
    </tr>
    <tr>
      <td scope="row" title="Intenta corregir errores ortográficos t&iacute;picos en el correo">Sugerido</td>
      <td>{did_you_mean}</td>
    </tr>
    <tr>
      <td scope="row" title="Caracter&isticas">Caracter&iacute;sticas</td>
      <td>
        {characteristics}
      </td>
    </tr>
   </tbody>
  </table>
</div>
"""
raw="""
<!doctype html>
<html lang="en">
  <head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" integrity="sha384-MCw98/SFnGE8fJT3GXwEOngsV7Zt27NXFoaoApmYm81iuXoPkFOJwJ8ERdknLPMO" crossorigin="anonymous">

    <title>Verificador de Direcciones de Correo Electr&oacute;nico</title>
  </head>
  <body>
      <div class="container">
        {{status}}
      </div>
      <form class="container" action="{validateurl}" method="POST">
        <div class="form-group">
            <label for="textarea" class="form-control-lg">Emails</label>
            <textarea class="form-control form-control-lg" rows="3" name="emails" placeholder="name1@company.com, name2@company.com, ...">{{emails}}</textarea>
        </div>
      <button type="submit" class="btn btn-primary">Validar</button>
    </form>
    <div class="container">
        {{messages}}
    </div>
    <div class="form-group container">
      <label for="textarea" class="form-control-lg">Validadas</label>
      <textarea class="form-control form-control-lg" rows="3" readonly>{{cleanedup}}</textarea>
    </div>
    <div class="container">
      <label for="textarea" class="form-control-lg">Detalle</label>
      <div class="row">
        <div class="col-4">
          <div class="list-group" id="list-tab" role="tablist">
            {{resultlist}}
          </div>
        </div>
        <div class="col-8">
          <div class="tab-content" id="nav-tabContent">
            {{resulttabs}}
          </div>
        </div>
      </div>
    </div>
    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.3/umd/popper.min.js" integrity="sha384-ZMP7rVo3mIykV+2+9J3UJ46jBk0WLaUAdn689aCwoqbBJiSnjAK/l8WvCWPIPm49" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/js/bootstrap.min.js" integrity="sha384-ChfqqxuZUCnJSK3+MXmPNIyE6ZbWh2IMqE241rYiqJxyMiZ6OW/JmZQ5stwEULTy" crossorigin="anonymous"></script>
  </body>
</html>
"""
root = raw.format(validateurl=validateurl)

class Characteristic(object):
  def __init__(self,show,href,level,title,name):
    self.show = show
    self.href = href
    self.level = level
    self.title = title
    self.name = name
  def __repr__(self):
    if self.show:
        return f"""<a target="_blank" href="{self.href}" class="badge badge-{self.level}" title="{self.title}">{self.name}</a>"""
    else:
        return ""

class Message(object):
    def __init__(self,level,msg):
        self.level = level
        self.msg = msg
    def __repr__(self):
        return f"""<div class="alert alert-{self.level}" role="alert">{self.msg}</div>"""

class Status(object):
    def __init__(self,level,tooltip,name):
        self.level = level
        self.tooltip = tooltip
        self.name = name
    def __repr__(self):
        return f"""<span class="badge badge-pill badge-{self.level}" title="{self.tooltip}">{self.name}</span>"""

def authRequired(func):
    """Make sure user is logged in before proceeding"""
    @functoolswraps(func)
    def wrapper_login_required(request):
        print("cookies {}".format(request.cookies))
        recAuth=request.cookies.get("authKey")
        if recAuth != authKey:
            return Response(f'Acceso denegado. Ingrese <a href="{authurl}">aqu&iacute;</a>',401)
        return func(request)
    return wrapper_login_required

def getParam(request,name):
    result = ""
    if request.args and name in request.args and request.args[name]:
        req = request.args[name]
        try:
            result = gzipdecompress(b64decode(req)).decode()
        except binasciiError:
            pass
        except zliberror:
            pass
        except EOFError:
            pass
    return result

@authRequired
def emailVerifierRoot(request):
    """Responds to any HTTP request.
    Args:
        request (flask.Request): HTTP request object.
    Returns:
        The response text or any set of values that can be turned into a
        Response object using
        `make_response <http://flask.pocoo.org/docs/0.12/api/#flask.Flask.make_response>`.
    """
    emails=getParam(request,"emails")
    cleanedup=getParam(request,"cleanedup")
    details=getParam(request,"details")
    errors=getParam(request,"errors")
    mock=request.cookies.get("mock") != "false"
    if mock:
        status = Status(
            level="secondary",
            tooltip="Estado simulado donde no se hacen consultas reales. Solo para la POC.",
            name="Simulado",
            )
    else:
        status = Status(
            level="primary",
            tooltip="Sistemas funcionando normalmente",
            name="Normal",
        )
    resultlist = ""
    resulttabs = ""
    iter = 0
    messages= ""
    for err in errors.split(","):
        if not err:
            continue
        messages += str(Message(level="danger",msg=err))
    djson = []
    if details:
        djson = jsonloads(details)
    if emails and not cleanedup:
        messages += str(Message(level="warning",msg="No se encontraron emails v&aacute;lidos"))
    for detail in djson:
        if not detail or not "email" in detail:
            continue
        resultlist += resultitem.format(iter=iter,email=detail["email"],color=detail["color"])
        detail["characteristics"] = str(Characteristic(
            show=detail["free"],
            href="https://es.wikipedia.org/wiki/Correo_electr%C3%B3nico#Servicios_de_correo_electr%C3%B3nico",
            level="info",
            title="La direcci&oacute;n de correo se puede obtener de manera gratis",
            name="Gratis",
            ))
        detail["characteristics"] += str(Characteristic(
            show=detail["catch_all"]=="None",
            href="https://es.wikipedia.org/wiki/Catch-all",
            level="info",
            title="No se ha verificado si la direcci&oacute;n de correo es un correo por defecto para recibir correo no deseado",
            name="Catch all is disabled",
        ))
        detail["characteristics"] += str(Characteristic(
            show=detail["catch_all"],
            href="https://es.wikipedia.org/wiki/Catch-all",
            level="danger",
            title="La direcci&oacute;n de correo es un correo por defecto para recibir correo no deseado",
            name="Catch all",
        ))
        detail["characteristics"] += str(Characteristic(
            show=detail["disposable"],
            href="https://es.wikipedia.org/wiki/Direcci%C3%B3n_correo_electronico_desechable",
            level="danger",
            title="La direcci&oacute;n de correo es de tipo desechable",
            name="Desechable",
        ))
        detail["characteristics"] += str(Characteristic(
            show=detail["format_valid"],
            href="https://en.wikipedia.org/wiki/Email_address",
            level="success",
            title="La direcci&oacute;n de correo tiene un formato v&aacute;lido para Internet",
            name="Formato v&aacute;lido",
        ))
        detail["characteristics"] += str(Characteristic(
            show=not detail["format_valid"],
            href="https://en.wikipedia.org/wiki/Email_address",
            level="danger",
            title="La direcci&oacute;n de correo no tiene formato v&aacute;lido para Internet",
            name="Formato inv&aacute;lido",
        ))
        detail["characteristics"] += str(Characteristic(
            show=detail["mx_found"],
            href="https://es.wikipedia.org/wiki/MX_(registro)",
            level="success",
            title="La direcci&oacute;n de correo tiene registro MX asociado",
            name="MX"
        ))
        detail["characteristics"] += str(Characteristic(
            show=not detail["mx_found"],
            href="https://es.wikipedia.org/wiki/MX_(registro)",
            level="danger",
            title="La direcci&oacute;n de correo tiene no tiene registro MX asociado",
            name="MX"
        ))
        detail["characteristics"] += str(Characteristic(
            show=detail["role"],
            href="https://es.wikipedia.org/wiki/Webmaster",
            level="info",
            title="La direcci&oacute;n de correo esta asociada a un rol espec&iacute;fico. Por ejemplo: Webmaster",
            name="Rol",
        ))
        detail["characteristics"] += str(Characteristic(
            show=detail["smtp_check"],
            href="https://es.wikipedia.org/wiki/Protocolo_para_transferencia_simple_de_correo",
            level="success",
            title="La direcci&oacute;n de correo pasa la prueba SMTP",
            name="SMTP",
        ))
        detail["characteristics"] += str(Characteristic(
            show=not detail["smtp_check"],
            href="https://es.wikipedia.org/wiki/Protocolo_para_transferencia_simple_de_correo",
            level="danger",
            title="La direcci&oacute;n de correo no pasa la prueba SMTP",
            name="SMTP",
        ))
        resulttabs += resulttabitem.format(iter=iter,**detail)
        iter += 1

    return root.format(
        emails=emails,
        cleanedup=cleanedup,
        resultlist=resultlist,
        resulttabs=resulttabs,
        messages=messages,
        status=status
    )

