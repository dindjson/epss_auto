#!/usr/bin/env/python

import gzip
import shutil

with gzip.open('epss_scores-2022-04-17.csv.gz', 'rb') as f_in:
	with open('newfile.csv', 'wb') as f_out:
		shutil.copyfileobj(f_in, f_out)