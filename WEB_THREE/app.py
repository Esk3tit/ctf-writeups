# coding=utf-8

from flask import render_template, render_template_string, flash, redirect, session, url_for, request, g, Markup, Response
from app import app
import uuid
import traceback
import os

def _generate_cowsay_file():
    return '/tmp/cow-' + str(uuid.uuid4())


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/cowsay')
def cowsay():
    filename_in = _generate_cowsay_file()
    filename_out = _generate_cowsay_file()
    with open(filename_in, 'w') as f:
        f.write(str(request.args.get('msg'))[:2000])

    # cowsay!
    os.system('cat ' + filename_in + ' | /usr/games/cowsay -TU -W 2000 > ' + filename_out + ' 2>&1')
    return redirect('/render?path=' + filename_out, code=302)


@app.route('/render')
def about():
    try:
        with open(request.args.get('path', 'layout.html'), 'r') as f:
            resp = render_template_string('''{% extends "layout.html" %}{% block content %}<div class="jumbo"><h1>Your cow says...</h1><code>''' + f.read() + '''</code><br><p><a href="/">do it again!!!!!!!!!</a></p></div>{% endblock %}''')

            # check if the user is trying to do something evil :((
            if u'OSUSEC{' in resp:
                resp = u'I see the flag in the response! Nice try.'

            return Response(response=resp, status=200)
    except:
        msg = 'We could not fetch your page! Sorry :(\n\n' + traceback.format_exc()
        return Response(response=msg, status=500, mimetype='text/plain')
