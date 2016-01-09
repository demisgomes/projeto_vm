import os
from flask import Flask, render_template, request, json
app = Flask(__name__)

@app.route('/')
def hello_world():
    return render_template('index.html')

@app.route('/criar',methods=['POST'])
def criar():
	try:
		ip2=""
		netmask2=""
		ip3=""
		netmask3=""
		ip4=""
		netmask4=""
		
		cpus=request.form['quantidade_cpus']
		memoria=request.form['memoria']
		ip1=request.form['ip1']
		netmask1=request.form['netmask1']
		if (request.form.get('ip2')!=None):
			ip2=request.form['ip2']
		if (request.form.get('netmask2')!=None):
			netmask2=request.form['netmask2']
		if (request.form.get('ip3')!=None):
			ip3=request.form['ip3']
		if (request.form.get('netmask3')!=None):
			netmask3=request.form['netmask3']
		if (request.form.get('ip4')!=None):
			ip4=request.form['ip4']
		if (request.form.get('netmask4')!=None):
			netmask4=request.form['netmask4']
		print "Memoria ", memoria, cpus, ip1, netmask1, ip2, netmask2, ip3, netmask3, ip4, netmask4
		os.chdir("../")
		os.system("bash ./vm_create.sh vm_00 "+cpus+" "+memoria)
		os.system("bash ./vm_configure.sh vm_00 "+ip1+" "+netmask1+" "+ip2+" "+netmask2+" "+ip3+" "+netmask3+" "+ip4+" "+netmask4)
		return "Hello World!"
	except Exception as e:
	        return json.dumps({'error':str(e)})

@app.route('/criado')
def fallback():
    return render_template('criado.html')

if __name__ == '__main__':
    app.run(debug=True, port=5001)
