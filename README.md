# nsx-rules-export

Written by Ron Rossman Jr (ronrossman@gmail.com)

A python3 script to export the Distributed Firewall rules information from NSX to a XLSX spreadsheet, with each "Policy Section" in the firewall recorded into its own sheet in the spreadsheet file.\
This script does take a LONG while to run as the NSX DFW is just one giant relationship map, with objects related to other objects until you finally get back to the source objects. This requires a lot of API calls for the full lookups for the object trees to be completed.

An attempt is made to query for each object in each area of a rule to fully develope a copy of the rule, using new lines in the cell for every item.

This was created as I couldn't find a vendor provided method to export the policy information in any useful way.
