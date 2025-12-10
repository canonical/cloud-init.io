from canonicalwebteam.flask_base.app import FlaskBase
from canonicalwebteam.flask_base.env import get_flask_env
import datetime
from flask import render_template


app = FlaskBase(
    __name__,
    "cloud-init.io",
    template_folder="../templates",
    static_folder="../static",
    template_404="404.html",
)

@app.route("/")
def index():
    return render_template("index.html")

@app.context_processor
def inject_today_date():
    return {"current_year": datetime.date.today().year}