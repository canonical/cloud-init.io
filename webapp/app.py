from canonicalwebteam.flask_base.app import FlaskBase
from canonicalwebteam.cookie_service import CookieConsent
from flask_caching import Cache
import datetime
from flask import render_template
from datetime import timedelta


app = FlaskBase(
    __name__,
    "cloud-init.io",
    template_folder="../templates",
    static_folder="../static",
    template_404="404.html",
)

# Configure Flask session
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=365)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True


# Initialize Flask-Caching
app.config["CACHE_TYPE"] = "SimpleCache"
cache = Cache(app)


# Set up cache functions for cookie consent service
def get_cache(key):
    return cache.get(key)


def set_cache(key, value, timeout):
    cache.set(key, value, timeout)


cookie_service = CookieConsent().init_app(
    app,
    get_cache_func=get_cache,
    set_cache_func=set_cache,
    start_health_check=True,
)

@app.route("/")
def index():
    return render_template("index.html")

@app.context_processor
def inject_today_date():
    return {"current_year": datetime.date.today().year}
