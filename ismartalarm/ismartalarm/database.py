# ismartalarm.py
# Project: pentesting
#
# Created by "Francesco Servida"
# Created on 19.04.18

import sqlite3

class ISmartAlarmDB:
    """
    Class to be used with sqlite3 to test for code outside of autopsy
    """
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)

    def parse_actions(self):
        print("Actions executed")
        result = self.conn.execute('SELECT date, action, IPUID, logType, sensorName, operator, profileName FROM TB_IPUDairy')
        return list(result)

    def parse_sensors(self):
        print("Sensor detections")
        result = self.conn.execute('SELECT date, sensorID, action, model, operator, name, logtype FROM TB_SensorDairy;')
        return list(result)

    def parse_user(self):
        print("User Actions")
        result = self.conn.execute('SELECT * FROM TB_userDairy ORDER BY date DESC')
        return list(result)

# from java.lang import Class
# from java.sql  import DriverManager, SQLException
# from java.util.logging import Level
# from org.sleuthkit.autopsy.ingest import IngestModule
#
#
# class ISmartAlarmDB:
#     """
#     Class to be used with autopsy's java JDBC
#     """
#     def __init__(self, db_path):
#         try:
#             Class.forName("org.sqlite.JDBC").newInstance()
#             self.conn = DriverManager.getConnection("jdbc:sqlite:%s" % db_path)
#         except SQLException as e:
#             # self.log(Level.INFO,
#             #          "Could not open database file (not SQLite) recentlyUsedApps.db3 (" + e.getMessage() + ")")
#             raise LookupError("Unable to Open DB")
#
#     def parse_actions(self):
#         stmt = self.conn.createStatement()
#         result = stmt.executeQuery('SELECT * FROM TB_IPUDairy ORDER BY date DESC')
#         while result.next():
#             yield result.getRowData()
#
#     def parse_sensors(self):
#         stmt = self.conn.createStatement()
#         result = stmt.executeQuery('SELECT * FROM TB_SensorDairy ORDER BY date DESC')
#         while result.next():
#             yield result.getRowData()
#
#     def parse_user(self):
#         stmt = self.conn.createStatement()
#         result = stmt.executeQuery('SELECT * FROM TB_userDairy ORDER BY date DESC')
#         while result.next():
#             yield result.getRowData()