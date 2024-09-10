# nsx-rules-export

Written by Ron Rossman Jr

A python3 script to export firewall rule information from NSX to a XLSX spreadsheet, with each "Policy Section" in the firewall recorded into its own sheet in the spreadsheet file.

An attempt is made to query for each object in each area of a rule to fully develope a copy of the rule, using new lines in the cell for every item.

This was created as I couldn't find a vendor provided method to export the policy information in any useful way.
