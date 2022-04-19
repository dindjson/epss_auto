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

# Banner
print('-'*60)

print("    __________  __________    ____                           ")
print("   / ____/ __ \/ ___/ ___/   / __ \____ ______________  _____")
print("  / __/ / /_/ /\__ \\__ \   / /_/ / __ `/ ___/ ___/ _ \/ ___/")
print(" / /___/ ____/___/ /__/ /  / ____/ /_/ / /  (__  )  __/ /    ")
print("/_____/_/    /____/____/  /_/    \__,_/_/  /____/\___/_/     ")
print("                                                             ")

print('-'*60)

# User input
print("For more options or assistance, use --help")
uin=input(f"File type?\nOptions:\n(0) gz\n(1) zip\n(3) Failsafe, uses local file. (dev option)\n")

# User input if check for file type.
if uin == '0':
	print(f"you selected the 'gz' file type.\nGenerating File...")

	with gzip.open('epss_scores-2022-04-16.gz', 'rb') as f_in:
		with open('newfile.csv' 'wb') as f_out:
			shutil.copyfileobj(f_in, f_out)
elif uin == '1':
	print(f"you selected the 'zip' file type.\nGenerating File...")

	zf = zipfile.ZipFile('epss_scores-2022-04-16.zip')
	dfZip = pandas.read_csv(zf.open('newfile.csv'))
elif uin == '3':
	pass
else:
	print("Meep. Unexpected.")
	sys.exit()

#Initiate pandas read_csv() function and store in a variable.
#header=1 is used to ignore the first row in the CSV. This is optional.
df = pandas.read_csv('epss_scores-2022-04-16.csv', header=1)
#print(df)

#Create dictionary to generate high scorers observed
high_scorers_dict = {}

#Fill dictionary with CVEs with an EPSS score recorded of >=0.9
for index, row in df.iterrows():
	if row['epss'] >= 0.9:
		high_scorers_dict[row['cve']] = row['epss']

#Print statements
print(len(high_scorers_dict))
print(df)