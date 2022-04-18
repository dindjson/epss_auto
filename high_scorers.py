#!/usr/bin/env/python

# Author: Ryan Cribelar
# Scope:  New CVEs from the Exploit Prediction Scoring System
# 		  that were identified with a high (>0.90) probability
#		  of being exploited in the wild.

#		  creats a dictionairy with CVE Id/EPSS Score key/value pair
# 		  called high_scorers_dict

#Only import required is pandas to read the CSV from EPSS
import pandas as pd

#Read CSV and store in df
df = pd.read_csv('newfile.csv', header=1)
#print(df)

#Banner
print('-'*50)

#Establish empty dictionary
high_scorers_dict = {}

#Iterate through each row in the CSV, if an EPSS value greater than or
#equal to 0.9 is discovered, it is added to the dictionary
for index, row in df.iterrows():
	if row['epss'] >= 0.9:
		#print(row['cve'], row['epss'])
		high_scorers_dict[row['cve']] = row['epss']

#Display results
userin=input("Cat out full dictionary output? y/n (Warning: may be long):")
if userin=='y':
	print(high_scorers_dict)
else:
	pass

print(f"new CVEs identified with a high probability\nfor exploitation in the wild:")
print(len(high_scorers_dict))