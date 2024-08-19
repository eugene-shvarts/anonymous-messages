import os
from traceback import format_exc

from flask import Flask, render_template, request, send_from_directory, jsonify, session, redirect, url_for, flash
import bcrypt

from cipher import deserialize_public_key, hybrid_encrypt, hybrid_decrypt, user_info_from_secret, secret_from_user_info, decrypt_private_key, encrypt_private_key
from constants import LOCAL_SSH_TUNNEL_PORT, MYSQL_PORT
from util import ConnectionContext, ConnectionSSHContext

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

## Configurations
mysql_config = {
    'user': os.environ.get('MYSQL_DB_USER'),
    'password': os.environ.get('MYSQL_DB_PASSWORD'),
    'db': os.environ.get('MYSQL_DB_DATABASE'),
    'host': os.environ.get('MYSQL_DB_HOST') if not app.debug else '127.0.0.1',
    'port': MYSQL_PORT if not app.debug else LOCAL_SSH_TUNNEL_PORT
}

tunnel_config = {
    'ssh_host': os.environ.get('SSH_HOST'),
    'ssh_username': os.environ.get('SSH_USER'),
    'ssh_password': os.environ.get('SSH_PASSWORD'),
    'local_bind_address': ('127.0.0.1', LOCAL_SSH_TUNNEL_PORT),
    'remote_bind_address': (os.environ.get('MYSQL_DB_HOST'), MYSQL_PORT)
}

connctx = ConnectionSSHContext(mysql_config, tunnel_config) if app.debug else ConnectionContext(mysql_config)

## Load questions from the database
with connctx as conn:
    conn.execute('SELECT text, label, id FROM questions')
    question_data = conn.fetchall()

all_questions = [
    {'text': result[0], 'label': result[1], 'id': result[2], 'placeholder': ''}
    for result in question_data
]

question_labels = [
    "favorite_memory",
    "lasting_impact",
    "shared_activity"
]

questions = [ q for q in all_questions if q['label'] in question_labels ]
questions.sort(key=lambda x: question_labels.index(x['label']))

questionmap = { q['id']: q for q in all_questions }

## Auxiliaries
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

## Routes
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
                conn.execute('SELECT id, public_key FROM persons WHERE fullname = %s', (full_name,))
                person_id, pubkey = conn.fetchone()

                conn.execute('SELECT group_id from responses ORDER BY id DESC LIMIT 1')
                group_id = conn.fetchone()
                if group_id is None:
                    group_id = 1
                else:
                    group_id = group_id[0] + 1

                for question, response in zip(questions, form_data.values()):
                    encrypted_response = hybrid_encrypt(response, deserialize_public_key(pubkey))
                    conn.execute(
                        '''INSERT INTO responses (person_id, question_id, group_id, response_text)
                        VALUES (%s, %s, %s, %s)''',
                        (person_id, question['id'], group_id, encrypted_response)
                    )
            return response_text
        else:
            # Render the form page
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

    if user_secret_key and user_name:
        pid, pw = user_info_from_secret(user_secret_key)
        with connctx as conn:
            conn.execute('SELECT encrypted_private_key FROM persons WHERE id = %s', (pid,))
            encrypted_private_key = conn.fetchone()[0]
            private_key = decrypt_private_key(encrypted_private_key, pw)

            conn.execute('SELECT id, question_id, group_id, response_text FROM responses WHERE person_id = %s', (pid,))
            responses = conn.fetchall()

        def response_gen():
            errs = []
            ids = []
            for rid, qid, gid, response in responses:
                try:
                    yield {
                        'question': questionmap[qid]['text'],
                        'sort_key': (-gid, rid),
                        'response': hybrid_decrypt(response, private_key)
                    }
                except:
                    errs.append(format_exc())
                    ids.append(rid)
            if len(errs) > 0:
                app.logger.error('\n'.join(['RESPONSE DECRYPTION ERRORS FOLLOW:'] + errs))
                app.logger.error(f'Error responses: {ids}')
        
        sorted_responses = sorted(response_gen(), key=lambda x: x['sort_key'])
        return render_template('me.html', authenticated=True, name=user_name, responses=sorted_responses)
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
            new_hash = bcrypt.hashpw(new_pw, bcrypt.gensalt()).decode()
            try:
                with connctx as conn:
                    conn.execute('SELECT encrypted_private_key FROM persons WHERE id = %s', (pid,))
                    
                    new_encrypted_private_key = encrypt_private_key(
                        decrypt_private_key(conn.fetchone()[0], pw),
                        new_pw
                    )

                    conn.execute('UPDATE persons SET secret_key_hash = %s WHERE id = %s', (new_hash, pid))
                    conn.execute('UPDATE persons SET encrypted_private_key = %s WHERE id = %s', (new_encrypted_private_key, pid))
            except:
                flash('An error occurred while resetting the secret key. Please try again.')
                app.logger.error(format_exc())
                return redirect(url_for('reset_secret_key'))
            session['user_secret_key'] = new_secret
            flash(f'Your new secret key is {new_secret}. It has been saved only locally to your browser; make sure you copy it securely before you navigate away.')
            return redirect(url_for('reset_secret_key'))
        else:
            flash('Invalid secret key. Please try again.')
            return redirect(url_for('reset_secret_key'))

def validate_user(secret_key):
    try:
        pid, pw = user_info_from_secret(secret_key)
        with connctx as conn:
            conn.execute('SELECT secret_key_hash, name FROM persons WHERE id = %s', (pid,))
            result = conn.fetchone()
            
        if result:
            secret_key_hash, name = result
            if bcrypt.checkpw(pw, secret_key_hash.encode()):
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
