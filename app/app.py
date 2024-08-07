import os
from traceback import format_exc

from flask import Flask, render_template, request, send_from_directory, jsonify
from flask_mysqldb import MySQL

from constants import LOCAL_SSH_TUNNEL_PORT, MYSQL_PORT
from util import ConnectionContext, ConnectionSSHContext

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

# MySQL configurations
app.config['MYSQL_USER'] = os.environ.get('MYSQL_DB_USER')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_DB_PASSWORD')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB_DATABASE')
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_DB_HOST') if not app.debug else '127.0.0.1'
app.config['MYSQL_PORT'] = MYSQL_PORT if not app.debug else LOCAL_SSH_TUNNEL_PORT

mysql = MySQL(app)
connctx = ConnectionSSHContext(mysql) if app.debug else ConnectionContext(mysql)

question_labels = [
    "favorite_memory",
    "lasting_impact",
    "shadow_aspect"
]

questions = []
# TODO force the questions into the specified order
def set_questions():
    if len(questions) > 0:
        return questions
    
    with connctx as conn:
        cur = conn.cursor()
        cur.execute('SELECT question_text, question_label FROM questions')
        questions.extend([
            {'text': result[0], 'label': result[1], 'placeholder': ''}
            for result in cur.fetchall()
            if result[1] in question_labels
        ])
    return questions

modal_text = """You can provide anonymous reflections to your fellow unicorns!
When we meet each other so deeply, and so briefly, it can be powerful, sweet, and perhaps transformational to understand how we showed up.

Click through anyone's photo to leave reflections for them, and answer whichever questions you want to.

To view reflections left for you, go to unicornparade.xyz/me"""

def error_return(**metas):
    err_str = format_exc()
    if len(metas) > 0:
        err_str = '\n'.join([err_str] + [f'{k}: {v}' for k, v in metas.items()])
    app.logger.error(err_str)    
    return jsonify({"error": "An error occurred while processing your request."}), 500


@app.route('/')
def home():
    image_files = os.listdir('static')
    images = [{'filename': f, 'firstname': f.split('.')[0].split('-')[0]} for f in image_files if f.endswith('.jpg')]
    return render_template('select.html', images=images, modal_text=modal_text)

@app.route('/people/<full_name>', methods=['GET', 'POST'])
def people(full_name):
    if request.method == 'POST':
        # Process form data
        form_data = request.form
        response_text = f"Responses for {full_name.split('-')[0].title()}:\n\n"
        for question in questions:
            response_text += f"{question['text']}\n{form_data.get(question['label'], 'No response')}\n\n"
        return response_text
    else:
        # Render the form page
        set_questions()
        return render_template('person.html', full_name=full_name, questions=questions)

@app.route('/favicon.ico') 
def favicon(): 
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )

# test to validate mysql works
@app.route('/testmysql/<bar>', methods=['GET'])
def testmysql(bar):
    try:
        with connctx as conn:
            cur = conn.cursor()
            cur.execute(
                '''INSERT INTO foo (contents)
                VALUES (%s)''',
                (bar,)
            )
            conn.commit()
            cur.execute('SELECT * FROM foo')
            return jsonify(cur.fetchall())
    except:
        return error_return()

if __name__ == '__main__':
    app.run(debug=True)
