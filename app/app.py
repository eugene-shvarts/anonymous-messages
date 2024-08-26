from itertools import groupby
import os
from traceback import format_exc

from flask import Flask, render_template, request, send_from_directory, jsonify, session, redirect, url_for, flash
import bcrypt

from cipher import deserialize_public_key, hybrid_encrypt, hybrid_decrypt, user_info_from_secret, secret_from_user_info, decrypt_private_key, encrypt_private_key
from constants import MYSQL_PORT, USER_SECRET_KEY_LENGTH
from model import Person, Response, Question
from util import ConnectionContext

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

## Configurations
mysql_config = {
    'user': os.environ.get('MYSQL_DB_USER'),
    'password': os.environ.get('MYSQL_DB_PASSWORD'),
    'db': os.environ.get('MYSQL_DB_DATABASE'),
    'host': os.environ.get('MYSQL_DB_HOST'),
    'port': MYSQL_PORT
}

connctx = ConnectionContext(mysql_config)

## Load questions from the database
with connctx as conn:
    all_questions = Question.get_all(conn)

question_labels = [
    "favorite_memory",
    "lasting_impact",
    "shared_activity",
    "anything_else"
]

questions = [ q for q in all_questions if q.label in question_labels ]
questions.sort(key=lambda x: question_labels.index(x.label))

questionmap = { q.id: q for q in all_questions }

## Auxiliaries
modal_text = """You can provide anonymous reflections to your fellow unicorns!
When we meet each other so deeply, and so briefly, it can be powerful, sweet, and perhaps transformational to understand how we showed up.

Click through anyone's photo to leave reflections for them, and answer whichever questions you want to.

To view reflections left for you, click "My reflections", or go to unicornparade.xyz/me"""

def error_return(**metas):
    err_str = format_exc()
    if len(metas) > 0:
        err_str = '\n'.join([err_str] + [f'{k}: {v}' for k, v in metas.items()])
    app.logger.error(err_str)    
    return jsonify({"error": "An error occurred while processing your request."}), 500

## Routes
@app.route('/')
def home():
    try:
        image_files = os.listdir(os.path.join(app.root_path, 'static'))
        images = sorted(
            [
                {'filename': f, 'firstname': f.split('.')[0].split('-')[0]}
                for f in image_files
                if any(f.endswith(ext) for ext in ['.jpg', '.jpeg', '.png'])
            ],
            key=lambda x: x['firstname']
        )
        return render_template('select.html', images=images, modal_text=modal_text.replace('\n', '<br>'))
    except:
        return error_return()

@app.route('/people/<full_name>', methods=['GET', 'POST'])
def people(full_name):
    try:
        if request.method == 'POST':
            # Process form data
            form_data = request.form
            response_text = f"Submitted responses for {full_name.split('-')[0].title()}!"
            with connctx as conn:
                person = Person.get_by_fullname(conn, full_name)
                group_id = Response.next_group_id(conn)

                for question, response in zip(questions, form_data.values()):
                    encrypted_response = hybrid_encrypt(response, deserialize_public_key(person.public_key))
                    Response(person.id, question.id, group_id, encrypted_response).insert(conn)
            return response_text
        else:
            # Render the form page
            return render_template('person.html', full_name=full_name, questions=questions)
    except:
        return error_return()
    
@app.route('/me', methods=['POST'])
def post_me():
    user_secret_key = request.form.get('user_secret_key')
    if user_secret_key:
        person, validation_error = validate_user(user_secret_key)
        if person:
            session['user_secret_key'] = user_secret_key
            return redirect(url_for('get_me'))
        else:
            error = validation_error
    else:
        error = "Please provide a secret key."

    return render_template('me.html', authenticated=False, error=error)

@app.route('/me', methods=['GET'])
def get_me():
    try:
        user_secret_key = session.get('user_secret_key')
        if user_secret_key:
            person, validation_error = validate_user(user_secret_key)
            if not person:
                return render_template('me.html', authenticated=False, error=validation_error)
        else:
            return render_template('me.html', authenticated=False)

        pid, pw = user_info_from_secret(user_secret_key)
        private_key = decrypt_private_key(person.encrypted_private_key, pw)

        with connctx as conn:
            responses = Response.get_by_person(conn, pid)

        def response_gen():
            ids = []
            for response in responses:
                try:
                    yield {
                        'question': questionmap[response.question_id].text,
                        'sort_key': (-response.group_id, response.id),
                        'response': hybrid_decrypt(response.encrypted_text, private_key).replace('\n', '<br>')
                    }
                except:
                    ids.append(response.id)
                    # app.logger.error(format_exc())
            if len(ids) > 0:
                app.logger.error(f'Error decrypting {len(ids)} responses for {pid}: {ids}')
        
        sorted_responses = sorted(response_gen(), key=lambda x: x['sort_key'])
        grouped_responses = [list(g) for _, g in groupby(sorted_responses, key=lambda x: x['sort_key'][0])]
        return render_template('me.html', authenticated=True, name=person.name.capitalize(), responses=grouped_responses)
    except:
        return render_template('me.html', authenticated=False, error="An error occurred while loading responses, try refreshing?")
    
    
@app.route('/reset', methods=['GET', 'POST'])
def reset_secret_key():
    if request.method == 'GET':
        return render_template('reset.html')
    elif request.method == 'POST':
        secret_key = request.form['secret_key']
        person, validation_error = validate_user(secret_key)
        if person:
            pid, old_pw = user_info_from_secret(secret_key)
            new_pw = os.urandom(USER_SECRET_KEY_LENGTH)
            new_secret = secret_from_user_info(pid, new_pw)
            new_hash = bcrypt.hashpw(new_pw, bcrypt.gensalt()).decode()
            try:
                with connctx as conn:
                    old_encrypted_private_key = Person.get(conn, pid).encrypted_private_key
                    new_encrypted_private_key = encrypt_private_key(
                        decrypt_private_key(old_encrypted_private_key, old_pw),
                        new_pw
                    )

                    conn.execute('UPDATE persons SET secret_key_hash = %s WHERE id = %s', (new_hash, pid))
                    conn.execute('UPDATE persons SET encrypted_private_key = %s WHERE id = %s', (new_encrypted_private_key, pid))
            except:
                flash('An error occurred while resetting the secret key. Please try again.')
                app.logger.error(format_exc())
                return redirect(url_for('reset_secret_key'))
            session['user_secret_key'] = new_secret
            flash('Your new secret key is')
            flash(new_secret, 'secret')
            flash('It has been saved only locally to your browser; make sure you copy it securely before you navigate away.')
            return redirect(url_for('reset_secret_key'))
        else:
            flash(f'{validation_error} Please try again.')
            return redirect(url_for('reset_secret_key'))

def validate_user(secret_key):
    try:
        pid, pw = user_info_from_secret(secret_key)
        with connctx as conn:
            person = Person.get(conn, pid)
            
        if person and bcrypt.checkpw(pw, person.secret_key_hash.encode()):
            return person, None
        else:
            return None, "Invalid secret key."
    except:
        app.logger.error(format_exc())
        return None, "An error occurred while validating; try refreshing?"

@app.route('/favicon.ico') 
def favicon(): 
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )

# test to validate mysql works
# @app.route('/testmysql/<bar>', methods=['GET'])
# def testmysql(bar):
#     try:
#         with connctx as conn:
#             conn.execute(
#                 '''INSERT INTO foo (contents)
#                 VALUES (%s)''',
#                 (bar,)
#             )
#             conn.execute('SELECT * FROM foo')
#             return jsonify(cur.fetchall())
#     except:
#         return error_return()

if __name__ == '__main__':
    app.run(debug=True)
