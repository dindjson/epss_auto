#!/usr/bin/env/python

# Author: Ryan Cribelar
# Scope:  EPSS Parser is designed to intake a compressed data
#		  sheet containing the newest exploit probability
#		  scoring for CVEs and parse it for useful information
#		  specific to your environment.

# Imports
import pandas
import sys
import gzip
import shutil
import zipfile
import nvdlib
import csv
from tqdm import tqdm
from collections import OrderedDict

# Banner
print('-'*60)

print("    __________  __________    ____                           ")
print("   / ____/ __ \/ ___/ ___/   / __ \____ ______________  _____")
print("  / __/ / /_/ /\__ \\__ \   / /_/ / __ `/ ___/ ___/ _ \/ ___/")
print(" / /___/ ____/___/ /__/ /  / ____/ /_/ / /  (__  )  __/ /    ")
print("/_____/_/    /____/____/  /_/    \__,_/_/  /____/\___/_/     ")
print("                                                             ")

print('-'*60)

ret=True

# User input if check for file type.
while ret == True:
	print("For more options or assistance, use --h or --help")
	uin=input(f"File type?\nOptions:\n(0) gz\n(1) zip\n(3) Manual Failsafe (see README)\n")

	if uin == '0':
		print(f"you selected the 'gz' file type.\nGenerating File...")

		#Using the gzip library open() function to grab the epss file and write out to csv.
		with gzip.open('epss_scores-2022-04-17.csv.gz', 'rb') as f_in:
			with open('parser_epss_results.csv', 'wb') as f_out:
				shutil.copyfileobj(f_in, f_out)

		ret=False
	elif uin == '1':
		print(f"you selected the 'zip' file type.\nGenerating File...")

		#Using zipfile library ZipFile() function to grab the epss file and write out to csv.
		zf = zipfile.ZipFile('epss_scores-2022-04-17.zip')
		dfZip = pandas.read_csv(zf.open('parser_epss_results.csv'))
		ret=False
	elif uin == '3':
		pass
	elif uin =='--help':
		print("Excited to build out this menu and further options :) Please stay tuned.")
	elif uin == '--h':
		print("Excited to build out this menu and further options :) Please stay tuned.")
	else:
		print("Meep. Unexpected.")
		sys.exit()

#Initiate pandas read_csv() function and store in a variable.
#header=1 is used to ignore the first row in the CSV. This is optional.

df = pandas.read_csv('parser_epss_results.csv', header=1)

#Create dictionary to generate high scorers observed
high_scorers_dict = {}

#Fill dictionary with CVEs with an EPSS score recorded of >=0.9
for index, row in df.iterrows():
	if row['epss'] >= 0.9:
		high_scorers_dict[row['cve']] = row['epss']

#Print statements
print('-'*60)
print("Amount of new CVEs with a generated EPSS score of >=0.9")
print('-'*60)
print(len(high_scorers_dict))
print('-'*60)
print("Summary of the data:")
print(df)
print('-'*60)

uin2 = input(f"You now have a dictionary of CVEs/EPSS score key/value pair\nWhat would you like to do?\n (0) NVD Library Information\n")


print("Generating file containing NVD references for high probability CVEs...")

if uin == '0':
	print("Generating lists...")
	sleep(0.2)
	cve_li = []
	nvd_li = []
	length = 20

	print("Injecting keys...")
	sleep(0.2)
	for key in high_scorers_dict.keys():
		cve_li.append(str(key))

	print("Calling NVDLib... This might take a while...")
	i = 0
	while i <= len(cve_li):
		r = nvdlib.getCVE(cve_li[i])
		i += 1
		nvd_li.append(r)

		pbar = tqdm(total=length) # Init pbar
		for i in range(length):
  			pbar.update(n=1) # Increments counter

	print("Filling Dictionary!...")
	sleep(0.2)
	nvd_ref_dict = {cve_li[i]: nvd_li[i] for i in range(len(nvd_li))}

	print("Writing file!...")
	sleep(0.2)
	with open('cve_nvd_ref.csv','w', newline='') as f:
	    w = csv.writer(f)
	    w.writerows(nvd_ref_dict.items())	

	print("File generated! Check working directory.")
else:
	print("Wo what happened??...")

#Gather NVD information from nvdlib library getCVE() function
#for key in high_scorers_dict.keys():
#	nvd_cve_li.append(nvdlib.getCVE(high_scorers_dict[key]))
#	cve_li.append(high_scorers_dict[key])

'''
Notes for next time:

need to re-organize script to where a CVE list is iterable through user-input,
and then the NVDLib function needs to be called.

As of right now, the script works, however containing the NVDLib function the way 
it is built now causes the script to run far too slow to scale effectively.

Channel your inner bash
'''
