from flask import flash
from flask_appbuilder.security.manager import SecurityManager

ALLOWED_DOMAINS = {"spd.tech", "liquidrewards.com"}

class CustomSecurityManager(SecurityManager):
    def oauth_user_info(self, provider, response=None):
        if provider == 'google':
            me = self.appbuilder.sm.oauth_remotes[provider].get('userinfo').json()
            email = me['email']
            domain = email.split('@')[-1]

            if domain not in ALLOWED_DOMAINS:
                flash(f"Email domain '{domain}' is not allowed to login.", "danger")
                return None

            return {
                'username': email,
                'email': email,
                'first_name': me.get('given_name', ''),
                'last_name': me.get('family_name', ''),
            }
