# MSc Autopsy Plugins

This repository is a collection of plugins for Autopsy forensic software and standalone scripts to parse artifacts from iSmartalarm, QBee, Arlo and Wink devices developed in the context of my master's thesis (which you can find here: [https://github.com/fservida/msc_thesis](https://github.com/fservida/msc_thesis) beware it's in French).

## iSmartalarm
### Autopsy plugins
Parses:
 - credentials from Android app settings.
 - events from app database.

### standalone script (ismartalarm/ismartalarm.py)
Parses events from diagnostic file of cubeone (cf. CVE-2018-16224 and [https://github.com/fservida/msc_thesis_vulnerabilities/tree/master/ismartalarm/ismartalarm_network_diag](https://github.com/fservida/msc_thesis_vulnerabilities/tree/master/ismartalarm/ismartalarm_network_diag) for more info about obtaining the logs)

## QBee
Decrypts QBee's (and Swisscom Home Application) settings database and parses user credentials.
Available as Autopsy plugin as well as standalone script.

## Arlo
Parses:
 - user info from settings file of Arlo's Android Application.
 - ! cached data parsing (eg. thumbnails) is available as a setting but is broken as of now and will make the ingest job hang, ensure it's disabled before running the plugin.

## Wink
Standalone script, parses events from Wink Android App "persistence" db.

## Installation
Copy all the folders to the python plugin folder of your Autopsy installation.

### QBee
The QBee plugins depends on a compiled executable to be present in the plugin folder, you can compile it using CXFreeze ant the provided setup.py file.
The provided release zip contains a precompiled version.


# Credits
This plugins were developed in the context of my master's thesis, thanks to University of Lausanne, DFRWS and Seculabs SA for the technical and financial support.

# License
These plugins are available under GPL License, cf. License file for details.

Feel free to leave your feedback and/or contribute back.
