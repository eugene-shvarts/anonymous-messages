import os
from traceback import format_exc

from flask import Flask, render_template, request, send_from_directory, jsonify, session, redirect, url_for, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from base64 import b64decode

from cipher import deserialize_public_key, hybrid_encrypt, hybrid_decrypt, user_info_from_secret, secret_from_user_info, decrypt_private_key, encrypt_private_key
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

#bcrypt configurations
bcrypt = Bcrypt(app)

question_labels = [
    "favorite_memory",
    "lasting_impact",
    "shadow_aspect"
]

questions = []
questionmap = {}
# TODO force the questions into the specified order
def set_questions():
    if len(questions) > 0:
        return questions
    
    with connctx as conn:
        cur = conn.cursor()
        cur.execute('SELECT question_text, question_label, id FROM questions')
        questions.extend([
            {'text': result[0], 'label': result[1], 'id': result[2], 'placeholder': ''}
            for result in cur.fetchall()
            if result[1] in question_labels
        ])
        for q in questions:
            questionmap[int(q['id'])] = q
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
    try:
        image_files = os.listdir(os.path.join(app.root_path, 'static'))
        images = [{'filename': f, 'firstname': f.split('.')[0].split('-')[0]} for f in image_files if f.endswith('.jpg')]
        return render_template('select.html', images=images, modal_text=modal_text)
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
                cur = conn.cursor()
                cur.execute('SELECT id, public_key FROM persons WHERE fullname = %s', (full_name,))
                person_id, pubkey = cur.fetchone()
                for question, response in zip(questions, form_data.values()):
                    cur.execute(
                        '''INSERT INTO responses (person_id, question_id, response_text)
                        VALUES (%s, %s, %s)''',
                        (person_id, question['id'], hybrid_encrypt(response, deserialize_public_key(pubkey)))
                    )
                conn.commit()
            return response_text
        else:
            # Render the form page
            set_questions()
            return render_template('person.html', full_name=full_name, questions=questions)
    except:
        return error_return()
    
@app.route('/me', methods=['GET', 'POST'])
def me():
    error = None
    if request.method == 'POST':
        user_secret_key = request.form.get('user_secret_key')
        if user_secret_key:
            # Validate the secret key
            user_info = validate_user(user_secret_key)
            if user_info:
                session['user_secret_key'] = user_secret_key
                session['user_name'] = user_info['name']
                return redirect(url_for('me'))
            else:
                error = "Invalid secret key. Please try again."
    
    user_secret_key = session.get('user_secret_key')
    user_name = session.get('user_name')
    # todo: try-catch each response, in case of decryption error
    if user_secret_key and user_name:
        with connctx as conn:
            with conn.cursor() as cur:
                pid, pw = user_info_from_secret(user_secret_key)
                cur.execute('SELECT encrypted_private_key FROM persons WHERE id = %s', (pid,))
                encrypted_private_key = cur.fetchone()[0]
                private_key = decrypt_private_key(encrypted_private_key, pw)

                cur.execute('SELECT question_id, response_text FROM responses WHERE person_id = %s', (pid,))

                def response_gen():
                    for qid, response in cur.fetchall():
                        try:
                            yield {
                                'question': questionmap[qid]['text'],
                                'response': hybrid_decrypt(response, private_key)
                            }
                        except:
                            continue

                responses = reversed(list(response_gen()))
        return render_template('me.html', authenticated=True, name=user_name, responses=responses)
    else:
        session.pop('user_secret_key', None)
        session.pop('user_name', None)
        return render_template('me.html', authenticated=False, error=error)
    
@app.route('/reset', methods=['GET', 'POST'])
def reset_secret_key():
    if request.method == 'GET':
        return render_template('reset.html')
    elif request.method == 'POST':
        secret_key = request.form['secret_key']
        if validate_user(secret_key):
            pid, pw = user_info_from_secret(secret_key)
            new_pw = os.urandom(18)
            new_secret = secret_from_user_info(pid, new_pw)
            new_hash = bcrypt.generate_password_hash(new_pw).decode()
            try:
                with connctx as conn:
                    with conn.cursor() as cur:
                        cur.execute('SELECT encrypted_private_key FROM persons WHERE id = %s', (pid,))
                        old_encrypted_private_key = cur.fetchone()[0]
                    new_encrypted_private_key = encrypt_private_key(
                        decrypt_private_key(old_encrypted_private_key, pw),
                        new_pw
                    )

                    with conn.cursor() as cur:
                        cur.execute('UPDATE persons SET secret_key_hash = %s WHERE id = %s', (new_hash, pid))
                        cur.execute('UPDATE persons SET encrypted_private_key = %s WHERE id = %s', (new_encrypted_private_key, pid))
                        conn.commit()
            except:
                flash('An error occurred while resetting the secret key. Please try again.')
                app.logger.error(format_exc())
                return redirect(url_for('reset_secret_key'))
            session['user_secret_key'] = new_secret
            flash(f'Your new secret key is {new_secret}. It has been saved locally to your browser; make sure you copy it securely before you navigate away.')
            return redirect(url_for('reset_secret_key'))
        else:
            flash('Invalid secret key. Please try again.')
            return redirect(url_for('reset_secret_key'))

def validate_user(secret_key):
    try:
        pid, pw = user_info_from_secret(secret_key)
        with connctx as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT secret_key_hash, name FROM persons WHERE id = %s', (pid,))
                result = cur.fetchone()
            
            if result:
                secret_key_hash, name = result
                if bcrypt.check_password_hash(secret_key_hash, pw):
                    return {"name": name.capitalize(), "user_id": pid}
                else:
                    return None
            else:
                return None
    except:
        app.logger.error(format_exc())
        return None

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
#             cur = conn.cursor()
#             cur.execute(
#                 '''INSERT INTO foo (contents)
#                 VALUES (%s)''',
#                 (bar,)
#             )
#             conn.commit()
#             cur.execute('SELECT * FROM foo')
#             return jsonify(cur.fetchall())
#     except:
#         return error_return()

if __name__ == '__main__':
    app.run(debug=True)
