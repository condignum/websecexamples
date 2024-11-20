import base64

#
# Ticket 5481729492: 
# The server's HTTP Basic Auth is currently not working, so this self-applying
# login hotfix is being made. User names and passwords will be transferred 
# base64-encoded in the HTTP Authorization header.
# The technical support team has provided the following examples:
#   Authorization: Basic YWRtaW46bXlzZWNyZXQ=               (admin:******)
#   Authorization: Basic dXNlcjpTdXBlclBhc3N3b3JkMSE=       (user:***************)
# In addition, we don't allow requests on this interface if they use the 
# "internal:internal" login, because this user is reserved for internal 
# backend traffic and must not be used here.
#
def is_valid_login(base64string):
    base64string = base64string.strip()

    # The string "aW50ZXJuYWw6aW50ZXJuYWw=" is the base64 representation of "internal:internal"
    # If we encounter this string, we reject the traffic immediately
    if base64string == "aW50ZXJuYWw6aW50ZXJuYWw=":
        print("Login rejected for user 'internal'")
        return False

    try:
        auth_string_decoded = base64.b64decode(base64string).decode()
        username, password = auth_string_decoded.split(":")
    except:
        print("Login rejected, invalid auth data: '{}'".format(base64string))
        return False

    # User names and passwords are hardcoded here in clear text, which is not the point of the
    # excercise: Normally a database lookup would happen here.
    # Note: the logins given are valid database entries.
    valid_logins = {
        "admin": "secret",
        "unicorn":"123456789a",
        "a_very_funny_1":"a_very_funny_1",
        "user": "SuperPassword1!",
        "internal": "internal",
    }

    if username not in valid_logins:
        print("Login rejected for user '{}' (wrong username)".format(username))   
        return False
    elif valid_logins[username] != password:    
        print("Login rejected for user '{}' (wrong password)".format(username))
        return False
    else:    
        print("Login accepted for user '{}'".format(username))
        return True

# Just for testing, not part of the excercise
if __name__ == "__main__":
    test_inputs = [
        "YWRtaW46c2VjcmV0",              # Valid
        "dXNlcjpTdXBlclBhc3N3b3JkMSE=",  # Valid
        "dGVzdDp0ZXN0",                  # Invalid
        "dXNlcjpqdXN0YWd1ZXNz",          # Invalid 
        "aW50ZXJuYWw6aW50ZXJuYWw=",      # Invalid
    ]

    for base64string in test_inputs:
        is_valid_login(base64string)
