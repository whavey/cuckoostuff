import sqlite3
from flask import *
storage_path ="/home/detbox/cuckoo/storage/analyses/"
app = Flask(__name__)
import webbrowser

@app.route("/")
def reports():
	conn = sqlite3.connect('/home/detbox/cuckoo/det-chamber/files/FinalLog.db')
	c = conn.cursor()
	c.execute("select * from LogResults")
	Results = [dict(file_name = row[0],
			file_location = row[1].split('/')[-3],
			html_location = row[1].split('/')[-4] + '/'+ row[1].split('/')[-3] + '/reports/report.html',
			date = row[2],
			cuckoo_score = row[3],
			j48_prediction = row[4],
			j48_dist = row[5],
			adaboost_prediction = row[6],
			adaboost_dist = row[7],
			kstar_prediction = row[8],
			kstar_dist = row[9],
			expected_prediction = row[10].split(',')[-1]) for row in c.fetchall()]
	conn.close()
	return render_template('results.html', Results = Results)

@app.route("/<path:path>")
def serve_page(path):
	return send_from_directory(storage_path,path)

@app.route("/decision_tree")
def serve_j48():
	return send_from_directory('/home/detbox/cuckoo/det-chamber/result_page/static/','decision_tree_j48.jpg')

@app.route("/distances")
def serve_distance():
	print 'yep'	

if __name__ == "__main__":
	webbrowser.open('localhost:5000')
	app.run(debug=True)
