import socket

from helpers import (
    secrets,
    message,
    render_template,
    getProfilePicture,
    Flask,
)


from routes.post import postBlueprint
from routes.user import userBlueprint
from routes.index import indexBlueprint
from routes.signup import signUpBlueprint
from routes.search import searchBlueprint
from routes.editPost import editPostBlueprint
from routes.searchBar import searchBarBlueprint
from routes.dashboard import dashboardBlueprint
from routes.verifyUser import verifyUserBlueprint
from routes.adminPanel import adminPanelBlueprint
from routes.createPost import createPostBlueprint
from routes.setUserRole import setUserRoleBlueprint
from routes.passwordReset import passwordResetBlueprint
from routes.changeUserName import changeUserNameBlueprint
from routes.changePassword import changePasswordBlueprint
from routes.adminPanelUsers import adminPanelUsersBlueprint
from routes.adminPanelPosts import adminPanelPostsBlueprint
from routes.accountSettings import accountSettingsBlueprint
from routes.adminPanelComments import adminPanelCommentsBlueprint
from routes.changeProfilePicture import changeProfilePictureBlueprint
from dbChecker import dbFolder, usersTable, postsTable, commentsTable
from flask_oidc import OpenIDConnect
from flask import url_for


dbFolder()
usersTable()
postsTable()
commentsTable()



app = Flask(__name__)
app.config.update({
    'SECRET_KEY': 'your_secret_key',
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',  # Path to your client secrets file
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,  # Set to True in production with HTTPS
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'flaskBlog',
})


oidc = OpenIDConnect(app)

def authenticate_user_with_oidc(username, password):
    try:
        # Keycloak supports standard OIDC authentication flow
        # Use the oidc.authenticate() method to authenticate the user
        oidc.authenticate(username, password)
        return True
    except Exception as e:
        print(f"Authentication failed: {str(e)}")
        return False

@app.context_processor
def utility_processor():
    getProfilePicture
    return dict(getProfilePicture=getProfilePicture)


@app.errorhandler(404)
def notFound(e):
    message("1", "404")
    return render_template("404.html"), 404
from helpers import (
    session,
    request,
    sqlite3,
    flash,
    message,
    redirect,
    addPoints,
    render_template,
    Blueprint,
    loginForm,
    sha256_crypt,
)

import requests

@app.route("/login/redirect=<direct>", methods=["GET", "POST"])
@oidc.require_login
def login(direct):
    direct = direct.replace("&", "/")
    if oidc.user_loggedin:
        userName = oidc.user_getfield("preferred_username")
        session["userName"] = userName
        message("1", f'USER: {session["oidc_auth_profile"]} ALREADY LOGGED IN')
        return redirect("/")
	
    form = loginForm(request.form)
    if request.method == 'POST' and form.validate():
        userName = oidc.user_getfield("preferred_username")
        #message("1", f"{userName}")
        message("1", f"{session['oidc_auth_profile']}")
        # Validate user credentials using OIDC

        # Example: Check if the user is in the database
        # Replace this with your OIDC user validation logic
        connection = sqlite3.connect("db/users.db")
        cursor = connection.cursor()
        cursor.execute(
            f'select * from users where lower(userName) = "{userName.lower()}"'
        )
        user = cursor.fetchone()
        if not user:
            message("1", f'USER: "{userName}" NOT FOUND')
            flash("User not found", "error")
        else:
            # Authenticate the user using OIDC
            # You may need to customize this based on your OIDC provider
            if authenticate_user_with_oidc(userName, password):
                session["userName"] = userName
                addPoints(1, userName)
                message("2", f'USER: "{userName}" LOGGED IN')
                flash(f"Welcome {userName}", "success")
                return redirect("/")
            else:
                message("1", "WRONG PASSWORD")
                flash("Wrong password", "error")

    return render_template("login.html", form=form, hideLogin=True)

@app.route('/test-logout', methods=['GET'])
@oidc.require_login
def test_logout():
    if "userName" in session:
        message("1", f'USER: "{session["userName"]}" LOGGED OUT')
        session.clear()
        message("1", f'USER: "{session}" LOGGED OUT')
        if oidc.user_loggedin:
           oidc.logout()
        return redirect("/")
    else:
            message("1", f"USER NOT LOGGED IN")
            return redirect("/")

app.register_blueprint(postBlueprint)
app.register_blueprint(userBlueprint)
app.register_blueprint(indexBlueprint)
app.register_blueprint(signUpBlueprint)
app.register_blueprint(searchBlueprint)
app.register_blueprint(editPostBlueprint)
app.register_blueprint(dashboardBlueprint)
app.register_blueprint(searchBarBlueprint)
app.register_blueprint(adminPanelBlueprint)
app.register_blueprint(createPostBlueprint)
app.register_blueprint(verifyUserBlueprint)
app.register_blueprint(setUserRoleBlueprint)
app.register_blueprint(passwordResetBlueprint)
app.register_blueprint(changeUserNameBlueprint)
app.register_blueprint(changePasswordBlueprint)
app.register_blueprint(adminPanelUsersBlueprint)
app.register_blueprint(adminPanelPostsBlueprint)
app.register_blueprint(accountSettingsBlueprint)
app.register_blueprint(adminPanelCommentsBlueprint)
app.register_blueprint(changeProfilePictureBlueprint)

match __name__:
    case "__main__":
        app.run(debug=True, host=socket.gethostbyname(socket.gethostname()))
