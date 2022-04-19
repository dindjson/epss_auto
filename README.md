EPSS Parser is designed to intake a compressed datasheet containing the newest exploit probability scoring for CVEs and parse it for useful information specific to your environment.

Script is a WIP at this time. If running it is your goal, you will need to manually update the file path locations until pre-determined options can be specified via the --help or -h option.

Scope:
0 - gz
1 - zip
3 - Manual Failsafe. Note: This option exists for folks who want an option in the script to select a personally named file after changing the syntax in the script.

Purpose:
Intakes a compressed EPSS datasheet and returns a CSV as well as building a dictionary/multiple dictionaries for the user with parsed information from selected input.
