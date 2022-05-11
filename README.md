# csv_to_ckl
Convert csv files generated with STIG viewer into checklist (ckl) files

There are plenty of tools for generating csv and xccdf files from STIG checklist (ckl) files.
I like to be able to visualize checklists using the viewer, and we generally get a rollup of all the STIGs in a single csv file (using the export csv option).

This is a work in progress:
Not all fields needed in a checklist file (xml format) can be determined from the csv file.  Things like STIGID and FILENAME are not in the export.  UUID and TargetKey dont seem to matter that much for importing generated ckl files.
Formatting of discussion, check text, fix text, etc still needs to be fine tuned
