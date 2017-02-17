#Python Imports
import re
import os
import sys
import sqlite3
import shutil
import hashlib
import urllib
import random
import subprocess
import json
import datetime
from collections import defaultdict

#Weka Imports
import weka.core.jvm as jvm
import weka.core.converters as converters
from weka.classifiers import Classifier
from weka.filters import Filter
import weka.plot.graph as graph

#Custom script imports
import arffControl

#Sqlite DB connection to cuckoo DB
connection = sqlite3.connect("/home/detbox/cuckoo/db/cuckoo.db")
cursor = connection.cursor()

#Sqlite DB connection to our Weka storage easy access DB
wekaConnection = sqlite3.connect("/home/detbox/cuckoo/det-chamber/files/FinalLog.db")
wekaCursor = wekaConnection.cursor()

#Create The table in our weka DB if it doesnt already exist
wekaCursor.execute("create table if not exists LogResults (file_name text, file_location text, date text, cuckoo_score text, j48_prediction text, j48_dist text, adaboost_prediction text, adaboost_dist text, kstar_prediction text, kstar_dist text, instance_values text, backlogged text)")

#Base storage path created by default by cuckoo
storage_path = "/home/detbox/cuckoo/storage/analyses/"

# Additional processing for arff conversion, DB update, and weka digestion
def process(num,name):
	full_path = storage_path + name[-2] + "_Report/" + name[-1]+"_Report_{}".format(num) + "/reports/report.json"
	# Open the report json file
	rep = open(full_path)
	
	# Loads the json cuckoo report to be read
	jdata = json.loads(rep.read())

	# Converts json report to arff format and returns arff instance string
	print "*Converting report to arff format."
	instance_values = arffControl.convert(jdata, name)

	# Set expectation (file-type_good)
	default_expectation = arffControl.expectation(jdata)

	print "*Updating results database."
	try:
		# Update weka DB for submission
		wekaCursor.execute("insert into LogResults values (?,?,?,?,?,?,?,?,?,?,?,?)",( name[-1],full_path.replace('report.json',''),datetime.datetime.now(),jdata["info"]["score"],'N/A','N/A','N/A','N/A','N/A','N/A', instance_values+default_expectation,'no') )
	except Exception,e:
		print "\nError on insert: {}".format(e)

# This moves the file and generates an arff file for Weka digestion
def saveReport(num,name):
	try:
		# Move report to proper location
		shutil.move(storage_path + name[-1]+"_Report_{}".format(num), storage_path + name[-2] + "_Report")
	except:
		incrementReportNumber(num+1,name)

	# Call additional processing
	process(num,name)	

# This assists the rename function move reports into appropriate directories
def incrementReportNumber(num,name):

	# Rename the storage folder with an incremented report number
	os.rename(storage_path + name[-1] +"_Report_{}".format(num-1), storage_path + name[-1]+"_Report_{}".format(num))

	# Attempt to save the report folder with the current name
	saveReport(num,name)


# This renames cuckoo reports and puts them into their original file structure 
def rename():
	print "*Renaming cuckoo storage folders to reflect submission names."
	for dirname in os.listdir(storage_path):
		try:
			# Pull the path of the submission from the cuckoo DB
                	cursor.execute("select target from tasks where id={}".format(int(dirname)))
			
			# Extract the name				
			name = cursor.fetchall()[0][0].split("/")

			# Set the directory name where the submission came from
			dir_path = storage_path + name[-2] + "_Report"
			
			# Check if there is already a storage file pertaining
			# reports of submissions from dir_path. Make it if not.
			if not os.path.exists(dir_path):
				os.makedirs(dir_path)
			
			# Set submission name
			rep_path = storage_path + name[-1]+"_Report_0"

			# Rename the task number folder to reflect submission name
			os.rename(storage_path + dirname, rep_path)
			
			# If this is a duplicate submission rename report with incremented num.
			# Otherwise just move the report to correct path. 
			if os.path.exists(dir_path + "/" + name[-1] + "_Report_0"):
				incrementReportNumber(1,name)
			else:
				saveReport(0,name)
		
		# Exceptions occur on trying to rename folders that arent task numbers already.
		except Exception, e:
			continue

# Weka Digestion: Trains a classifier using the arff_backlog and runs the classifer on the
# arff_test file to make predictions/classifications for each new instance (cuckoo submission).
def WekaRun():
	print "*Making classification(s) using Weka."

	#Start JVM
	jvm.start(class_path=[r'/home/detbox/weka-3-8-0/weka.jar',
			      r'/home/detbox/weka-3-8-0/weka-src.jar'])
	
	#Set that you will load an arff type file
	loader = converters.Loader(classname="weka.core.converters.ArffLoader")

	#Load an arff file as training data
	#Test that backlog exists for training
	try:
		Training_data = loader.load_file(r'/home/detbox/cuckoo/det-chamber/files/arff_backlog.arff')
	except Exception,e:
		print e
		if e == 'Dataset file does not exist':
			print '\nNo backlog. Weka classification cannot be made.'			
			return

	#Load an arff file as test data
	Test_data = loader.load_file(r'/home/detbox/cuckoo/arff_test.arff')

	#Filter duplicate instances
	remove = Filter(classname="weka.filters.unsupervised.instance.RemoveDuplicates")
	remove.inputformat(Training_data)
	filtered_training = remove.filter(Training_data)
	
	#prune arff_backlog file
	os.remove('/home/detbox/cuckoo/det-chamber/files/arff_backlog.arff')
	print >> open('/home/detbox/cuckoo/det-chamber/files/arff_backlog.arff','w'), filtered_training
	
	#Set class attribute as last one defined in arff file header
	#(This is what the instances will be classified as e.g 'pdf_bad')
	filtered_training.class_is_last()
	Test_data.class_is_last()

	#Define classifer being used (J48 for now)
	j48 = Classifier(classname="weka.classifiers.trees.J48", options=["-C", "0.3"])
	adaboost = Classifier(classname="weka.classifiers.meta.AdaBoostM1")
	kstar = Classifier(classname="weka.classifiers.lazy.KStar")

	#Train classifier on training data
	j48.build_classifier(filtered_training)
	adaboost.build_classifier(filtered_training)
	kstar.build_classifier(filtered_training)
	
	#Mapping of pred output to classification keywords
	class_mapping = {'0.0':'emf_good',
                                 '1.0':'emf_bad',
                                 '2.0':'jpg_good',
                                 '3.0':'jpg_bad',
                                 '4.0':'gif_good',
                                 '5.0':'gif_bad',
                                 '6.0':'doc_good',
                                 '7.0':'doc_bad',
                                 '8.0':'docx_good',
                                 '9.0':'docx_bad',
                                 '10.0':'WMF_good',
                                 '11.0':'WMF_bad',
                                 '12.0':'bmp_good',
                                 '13.0':'bmp_bad',
                                 '14.0':'pptx_good',
                                 '15.0':'pptx_bad',
                                 '16.0':'png_good',
                                 '17.0':'png_bad',
                                 '18.0':'xls_good',
                                 '19.0':'xls_bad',
                                 '20.0':'xlsx_good',
                                 '21.0':'xlsx_bad',
                                 '22.0':'pdf_good',
                                 '23.0':'pdf_bad',
                                 '24.0':'exe_good',
                                 '25.0':'exe_bad',
                                 '26.0':'zip_good',
                                 '27.0':'zip_bad',
                                 '28.0':'rtf_good',
                                 '29.0':'rtf_bad',
                                 '30.0':'ppt_good',
                                 '31.0':'ppt_bad',
                                 '32.0':'xml_good',
                                 '33.0':'xml_bad',
                                 '34.0':'xhtml_good',
                                 '35.0':'xhtml_bad',
				 '36.0':'tif_good',
				 '37.0':'tif_bad',
				 '38.0':'elf_good',
				 '39.0':'elf_bad',
				 '40.0':'sh_good',
				 '41:0':'sh_bad',
                                 '42.0':'other_good',
                                 '43.0':'other_bad'}

	#Enumerate Test data instances and make predictions/classifications
	for index,inst in enumerate(Test_data):

		#make prediction
		pred_j48 = j48.classify_instance(inst)
		pred_adaboost = adaboost.classify_instance(inst)
		pred_kstar = kstar.classify_instance(inst)

		#determine how close inst is to every potential prediction
		dist_j48 = j48.distribution_for_instance(inst)
		dist_adaboost = adaboost.distribution_for_instance(inst)
		dist_kstar = kstar.distribution_for_instance(inst)

		# Update weka DB with classifcation result
		# index corresponds to class mapping dictionary values.
		# inst contains the string with the comment to extract the file name.
		wekaCursor.execute("update LogResults set j48_prediction=? where instance_values=?",(class_mapping[str(pred_j48)],str(inst)))
		wekaCursor.execute("update LogResults set adaboost_prediction=? where instance_values=?",(class_mapping[str(pred_adaboost)],str(inst)))
		wekaCursor.execute("update LogResults set kstar_prediction=? where instance_values=?",(class_mapping[str(pred_kstar)],str(inst)))
		wekaCursor.execute("update LogResults set j48_dist=? where instance_values=?",(str(dist_j48),str(inst)))
		wekaCursor.execute("update LogResults set adaboost_dist=? where instance_values=?",(str(dist_adaboost),str(inst)))
		wekaCursor.execute("update LogResults set kstar_dist=? where instance_values=?",(str(dist_kstar),str(inst)))
			
	# Displays Decision tree used for classification
	graph.plot_dot_graph(j48.graph,'/home/detbox/cuckoo/det-chamber/result_page/static/decision_tree_j48.jpg')
	import kill_display

# On import in the main cuckoo script these main functions run
print "\n\nCuckoo Finished : Now running IVIII:"
print "-"*70
try:
	rename()	
	WekaRun()
except Exception,e:
	print "Error: {}".format(e)

wekaConnection.commit()
wekaConnection.close()
connection.close()

# Once a submission has been classified append classified instance to a backlog used as a 
# Training file for later weka digestion of cuckoo submissions.	
#filtered = filter(lambda x: not re.match(r'^\s*$',x), open('arff_test.arff').read().split('@data')[1])
for line in open('/home/detbox/cuckoo/arff_test.arff'):
	if line[0] != '@':
		print >> open('/home/detbox/cuckoo/det-chamber/files/arff_backlog.arff','a+'), line

os.remove('/home/detbox/cuckoo/arff_test.arff')
print "\n--Press Ctrl+c to run result Server--\n"
