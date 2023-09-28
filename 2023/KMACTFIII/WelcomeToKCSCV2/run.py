import json
from subprocess import check_output, STDOUT
from flask import Flask, render_template, request
app = Flask(__name__)

@app.route('/')
def index():
	cards = json.loads(open('data/former.txt', 'r').read())
	return render_template('index.html', cards=cards, card_len = len(cards))

@app.route('/contact', methods = ['GET', 'POST'])
def contact():
	if request.method == 'GET':
		return render_template('contact.html')
	elif request.method == 'POST':
		try:
			output = check_output(['./bin/advice', request.form['name'], request.form['advice']], stderr=STDOUT)
		except:
			output = 'Something wrong!'
		return render_template('contact.html', output=output.decode())

@app.route('/admin', methods = ['GET', 'POST'])
def admin():
	if request.method == 'GET':
		return render_template('admin.html')
	elif request.method == 'POST':
		try:
			output = check_output(['./bin/admin', request.form['username'], request.form['password']], stderr=STDOUT)
			if output==b'passed':
				output = open('/admin.flag', 'rb').read()
			else:
				output = b'Username or password is incorrect!'
		except Exception as e:
			output = b'Username or password is incorrect!'
		return render_template('admin.html', output=output.decode())

if __name__=='__main__':
	app.run(host='0.0.0.0')