import jwt

def key_for(token):
    header = jwt.get_unverified_header(token)
    return jwt.PyJWKClient(header["jku"]).get_signing_key_from_jwt(token)
