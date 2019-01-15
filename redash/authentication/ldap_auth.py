from redash.authentication.org_resolving import current_org
from redash.authentication import create_and_login_user, logout_and_redirect_to_index, get_next_path
from flask_login import current_user, login_required, login_user, logout_user
from flask import flash, redirect, render_template, request, url_for, Blueprint
from redash import settings
import logging
logger = logging.getLogger('ldap_auth')


try:
    from ldap3 import Server, Connection, SIMPLE
except ImportError:
    if settings.LDAP_LOGIN_ENABLED:
        logger.error("The ldap3 library was not found. This is required to use LDAP authentication (see requirements.txt).")
        exit()


blueprint = Blueprint('ldap_auth', __name__)


@blueprint.route("/ldap/login", methods=['GET', 'POST'])
def login(org_slug=None):
    index_url = url_for("redash.index", org_slug=org_slug)
    unsafe_next_path = request.args.get('next', index_url)
    next_path = get_next_path(unsafe_next_path)

    ldap_name_keys = list()
    if settings.LDAP_DISPLAY_NAME_KEYS:
        ldap_name_keys = [item.strip() for item in settings.LDAP_DISPLAY_NAME_KEYS.split(',')]
    else:
        ldap_name_keys = [settings.LDAP_DISPLAY_NAME_KEY]

    if not settings.LDAP_LOGIN_ENABLED:
        logger.error("Cannot use LDAP for login without being enabled in settings")
        return redirect(url_for('redash.index', next=next_path))

    if current_user.is_authenticated:
        return redirect(next_path)

    if request.method == 'POST':
        ldap_user = auth_ldap_user(request.form['email'], request.form['password'])

        if ldap_user is not None:

            user_display_name = ''
            ldap_name_fields = list()
            if settings.LDAP_DISPLAY_NAME_KEYS:
                ldap_name_fields = list()
                for k in [item.strip() for item in settings.LDAP_DISPLAY_NAME_KEYS.split(',')]:
                    ldap_name_fields.append(ldap_user[k][0])
                user_display_name = ' '.join(ldap_name_fields)
            else:
                user_display_name = ldap_user[settings.LDAP_DISPLAY_NAME_KEY][0]

            user = create_and_login_user(
                current_org,
                user_display_name,
                ldap_user[settings.LDAP_EMAIL_KEY][0]
            )
            if user is None:
                return logout_and_redirect_to_index()

            return redirect(next_path or url_for('redash.index'))
        else:
            flash("Incorrect credentials.")

    return render_template("login.html",
                           org_slug=org_slug,
                           next=next_path,
                           email=request.form.get('email', ''),
                           show_password_login=True,
                           username_prompt=settings.LDAP_CUSTOM_USERNAME_PROMPT,
                           hide_forgot_password=True)


def auth_ldap_user(username, password):
    server = Server(settings.LDAP_HOST_URL)

    # Support both single LDAP_DISPLAY_NAME_KEY and comma-delimited
    # form LDAP_DISPLAY_NAME_KEYS
    ldap_attrs = list()
    if settings.LDAP_DISPLAY_NAME_KEYS:
        ldap_attrs = [item.strip() for item in settings.LDAP_DISPLAY_NAME_KEYS.split(',')]
    else:
        ldap_attrs = [settings.LDAP_DISPLAY_NAME_KEY]
    ldap_attrs.append(settings.LDAP_EMAIL_KEY)

    if settings.LDAP_BIND_DN:
        conn = Connection(server, settings.LDAP_BIND_DN,
                          password=settings.LDAP_BIND_DN_PASSWORD,
                          authentication=SIMPLE, auto_bind=True)
    else:
        # Try anonymous Bind
        conn = Connection(server)
        conn.bind()

    conn.search(settings.LDAP_SEARCH_DN,
                settings.LDAP_SEARCH_TEMPLATE % {"username": username},
                attributes=ldap_attrs)

    if len(conn.entries) == 0:
        return None

    user = conn.entries[0]

    if not conn.rebind(user=user.entry_dn, password=password):
        return None

    return user
