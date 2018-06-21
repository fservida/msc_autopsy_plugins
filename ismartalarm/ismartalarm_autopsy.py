# Sample module in the public domain. Feel free to use this as a template
# for your modules (and you can remove this header and take complete credit
# and liability)
#
# Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Simple data source-level ingest module for Autopsy.
# Search for TODO for the things that you need to change
# See http://sleuthkit.org/autopsy/docs/api-docs/4.4/index.html for documentation

import jarray
import inspect

from java.lang import System, Class, IllegalArgumentException
from java.util.logging import Level
from java.io import File
from java.sql import DriverManager, SQLException
from javax.swing import JCheckBox, BoxLayout

from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.autopsy.datamodel import ContentUtils

import os
from time import mktime
from xml.dom import minidom

from ismartalarm.result import ISmartEventDB
from esc_generic import esc_generic_artifacts

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class ISmartAlarmIngestModuleFactory(IngestModuleFactoryAdapter):
    moduleName = "iSmartAlarm Analysis"

    def __init__(self):
        self.settings = None

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module for analysis of iSmartAlarm related DBs and logfiles\nby Francesco Servida - School of Criminal Justice, University of Lausanne, Switzerland"

    def getModuleVersionNumber(self):
        return "1.0"

    # TODO: Update class name to one that you create below
    def getDefaultIngestJobSettings(self):
        return ISmartAlarmIngestModuleSettings()

    # TODO: Keep enabled only if you need ingest job-specific settings UI
    def hasIngestJobSettingsPanel(self):
        return True

    # TODO: Update class names to ones that you create below
    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, ISmartAlarmIngestModuleSettings):
            raise IllegalArgumentException(
                "Expected settings argument to be instance of ISmartAlarmIngestModuleSettings")
        self.settings = settings
        return ISmartAlarmIngestModuleSettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ISmartAlarmIngestModule(self.settings)


# Data Source-level ingest module.  One gets created per data source.
class ISmartAlarmIngestModule(DataSourceIngestModule):
    _logger = Logger.getLogger(ISmartAlarmIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):

        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")

        # Settings
        self.log(Level.INFO, str(self.local_settings))

        # Get Case
        case = Case.getCurrentCase().getSleuthkitCase()

        # Add custom Artifact to blackboard
        # (cf: https://github.com/markmckinnon/Autopsy-Plugins/blob/master/CCM_RecentlyUsedApps/CCM_RecentlyUsedApps.py)
        # iSmartAlarm Specific Artifacts
        self.ismart_artifacts(case)

        # Generic Login Artifacts & Attributes
        esc_generic_artifacts(self, case)


        self.context = context

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/4.4/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    # TODO: Add your analysis code in here.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Use blackboard class to index blackboard artifacts for keyword search
        # blackboard = Case.getCurrentCase().getServices().getBlackboard() #we're not using indexing

        # Get case
        case = Case.getCurrentCase().getSleuthkitCase()

        # For our example, we will use FileManager to get all
        # files with the word "test"
        # in the name and then count and read them
        # FileManager API: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1casemodule_1_1services_1_1_file_manager.html
        fileManager = Case.getCurrentCase().getServices().getFileManager()

        db_files = fileManager.findFiles(dataSource, "iSmartAlarm.DB") if self.local_settings.get_parse_db() else []
        if self.local_settings.get_parse_settings():
            # Yes, Alerm, they have a typo in the file
            setting_file = fileManager.findFiles(dataSource, "iSmartAlermData.xml")
            mqtt_files = fileManager.findFiles(dataSource, "MQTT_Message_Service.xml%")
            reg_file = fileManager.findFiles(dataSource, "REG_KEY.xml")
        else:
            setting_file, mqtt_files, reg_file = [], [], []

        num_files = len(db_files) + len(setting_file) + len(mqtt_files) + len(reg_file)

        self.log(Level.INFO, "found " + str(num_files) + " files")
        progressBar.switchToDeterminate(num_files)
        file_count = 0

        # Parse DB
        if self.local_settings.get_parse_db():
            try:
                for file in db_files:

                    # Check if the user pressed cancel while we were busy
                    if self.context.isJobCancelled():
                        return IngestModule.ProcessResult.OK

                    self.log(Level.INFO, "Processing file: " + file.getName())
                    file_count += 1

                    # Make an artifact on the blackboard.
                    # Set the DB file as an "interesting file" : TSK_INTERESTING_FILE_HIT is a generic type of
                    # artifact.  Refer to the developer docs for other examples.
                    art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                    att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                                              ISmartAlarmIngestModuleFactory.moduleName, "iSmartAlarm")
                    art.addAttribute(att)

                    # Skip file is it is the journal file
                    if "journal" in file.getName():
                        continue

                    # try:
                    #     # index the artifact for keyword search
                    #     blackboard.indexArtifact(art)
                    # except Blackboard.BlackboardException as e:
                    #     self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

                    # Save the DB to disk
                    lcl_db_path = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
                    ContentUtils.writeToFile(file, File(lcl_db_path))

                    try:
                        Class.forName("org.sqlite.JDBC").newInstance()
                        conn = DriverManager.getConnection("jdbc:sqlite:%s" % lcl_db_path)
                    except SQLException as e:
                        self.log(Level.INFO,
                                 "Could not open database file (not SQLite) recentlyUsedApps.db3 (" + e.getMessage() + ")")
                        return IngestModule.ProcessResult.OK

                    self.events = []
                    self.devices = {}

                    try:
                        stmt = conn.createStatement()
                        ipu_dairy_sql = 'SELECT date, action, IPUID, logType, sensorName, operator, profileName FROM TB_IPUDairy'
                        # self.log(Level.INFO, ipu_dairy_sql)
                        result = stmt.executeQuery(ipu_dairy_sql)
                        # self.log(Level.INFO, "query TB_IPUDairy table")
                    except SQLException as e:
                        self.log(Level.INFO, "Error querying database for TB_IPUDairy table (" + e.getMessage() + ")")
                        return IngestModule.ProcessResult.OK

                    while result.next():
                        event = ISmartEventDB()
                        row = [
                            result.getLong('date'),
                            result.getString('action'),
                            result.getString('IPUID'),
                            result.getInt('logType'),
                            result.getString('sensorName'),
                            result.getString('operator'),
                            result.getString('profileName'),
                        ]
                        event.parse_ipu(row, self)
                        self.events.append(event)

                    try:
                        stmt = conn.createStatement()
                        sensors_diary_sql = 'SELECT sensorID, date, action, model, operator, name, logtype FROM TB_SensorDairy;'
                        # self.log(Level.INFO, sensors_diary_sql)
                        result = stmt.executeQuery(sensors_diary_sql)
                        # self.log(Level.INFO, "query TB_SensorDiary table")
                    except SQLException as e:
                        self.log(Level.INFO, "Error querying database for TB_SensorDiary table (" + e.getMessage() + ")")
                        return IngestModule.ProcessResult.OK

                    while result.next():
                        event = ISmartEventDB()
                        row = [
                            result.getLong('date'),
                            result.getString('sensorID'),
                            result.getString('action'),
                            result.getString('model'),
                            result.getString('operator'),
                            result.getString('name'),
                            result.getString('logtype'),
                        ]
                        event.parse_sensors(row, self)
                        self.events.append(event)

                    art_type_id = case.getArtifactTypeID("ESC_IOT_ISMARTALARM")
                    art_type = case.getArtifactType("ESC_IOT_ISMARTALARM")

                    for event in self.events:
                        # Artifact
                        art = file.newArtifact(art_type_id)
                        # Attributes
                        att_event_name_id = case.getAttributeType("ESC_IOT_ISMART_EVENT_NAME")
                        att_event_date_id = case.getAttributeType("ESC_IOT_ISMART_EVENT_DATE")
                        att_event_type_id = case.getAttributeType("ESC_IOT_ISMART_EVENT_TYPE")
                        att_event_device_id = case.getAttributeType("ESC_IOT_ISMART_EVENT_DEVICE")
                        att_event_device_type_id = case.getAttributeType("ESC_IOT_ISMART_EVENT_DEVICE_TYPE")

                        att_event_name = BlackboardAttribute(att_event_name_id,
                                                             ISmartAlarmIngestModuleFactory.moduleName, event.name)
                        att_event_date = BlackboardAttribute(att_event_date_id,
                                                             ISmartAlarmIngestModuleFactory.moduleName,
                                                             int(mktime(event.timestamp.timetuple())))
                        att_event_type = BlackboardAttribute(att_event_type_id,
                                                             ISmartAlarmIngestModuleFactory.moduleName, event.event_type)
                        att_event_device = BlackboardAttribute(att_event_device_id,
                                                               ISmartAlarmIngestModuleFactory.moduleName, event.device.name)
                        att_event_device_type = BlackboardAttribute(att_event_device_type_id,
                                                                    ISmartAlarmIngestModuleFactory.moduleName,
                                                                    event.device.device_type)

                        art.addAttribute(att_event_name)
                        art.addAttribute(att_event_date)
                        art.addAttribute(att_event_type)
                        art.addAttribute(att_event_device)
                        art.addAttribute(att_event_device_type)

                    IngestServices.getInstance().fireModuleDataEvent(
                        ModuleDataEvent(ISmartAlarmIngestModuleFactory.moduleName, art_type, None))
                    # Update the progress bar
                    progressBar.progress(file_count)

                    # Clean Up DB
                    stmt.close()
                    conn.close()
                    os.remove(lcl_db_path)
            except Exception:
                self.log(Level.INFO, "There was an error parsing the ismartalarm DB")

        # Settings & MQTT
        if self.local_settings.get_parse_settings():
            # Settings File
            for file in setting_file:

                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                self.log(Level.INFO, "Processing file: " + file.getName())
                file_count += 1

                # Make an artifact on the blackboard.
                # Set the DB file as an "interesting file" : TSK_INTERESTING_FILE_HIT is a generic type of
                # artifact.  Refer to the developer docs for other examples.
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                                          ISmartAlarmIngestModuleFactory.moduleName, "iSmartAlarm")
                art.addAttribute(att)

                # Write to file (any way to contour this?)
                lcl_setting_path = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".xml")
                ContentUtils.writeToFile(file, File(lcl_setting_path))

                a = minidom.parse(lcl_setting_path)
                tags = a.getElementsByTagName("string")
                ismart_logins = {}
                for tag in tags:
                    if tag.getAttribute('name') == "phoneNum":
                        ismart_logins['username'] = str(tag.firstChild.data)
                    elif tag.getAttribute('name') == "password":
                        ismart_logins['password'] = str(tag.firstChild.data)
                    elif tag.getAttribute('name') == "countryCode":
                        ismart_logins['country_code'] = str(tag.firstChild.data)

                art_type_id = case.getArtifactTypeID("ESC_GENERIC_LOGIN")
                art_type = case.getArtifactType("ESC_GENERIC_LOGIN")

                # Artifact
                art = file.newArtifact(art_type_id)
                # Attributes
                att_login_username_id = case.getAttributeType("ESC_GENERIC_LOGIN_USERNAME")
                att_login_secret_id = case.getAttributeType("ESC_GENERIC_LOGIN_SECRET")
                att_login_secret_type_id = case.getAttributeType("ESC_GENERIC_LOGIN_SECRET_TYPE")
                att_login_service_id = case.getAttributeType("ESC_GENERIC_LOGIN_SERVICE")
                att_login_remarks_id = case.getAttributeType("ESC_GENERIC_LOGIN_REMARKS")

                att_login_username = BlackboardAttribute(att_login_username_id,
                                                     ISmartAlarmIngestModuleFactory.moduleName, ismart_logins['username'])
                att_login_secret = BlackboardAttribute(att_login_secret_id,
                                                     ISmartAlarmIngestModuleFactory.moduleName,
                                                       ismart_logins['password'])
                att_login_secret_type = BlackboardAttribute(att_login_secret_type_id,
                                                     ISmartAlarmIngestModuleFactory.moduleName, "Password")
                att_login_service = BlackboardAttribute(att_login_service_id,
                                                       ISmartAlarmIngestModuleFactory.moduleName, "iSmartAlarm")
                att_login_remarks = BlackboardAttribute(att_login_remarks_id,
                                                            ISmartAlarmIngestModuleFactory.moduleName,
                                                        "Country Code: %s" % ismart_logins['country_code'])

                art.addAttribute(att_login_username)
                art.addAttribute(att_login_secret)
                art.addAttribute(att_login_secret_type)
                art.addAttribute(att_login_service)
                art.addAttribute(att_login_remarks)

                IngestServices.getInstance().fireModuleDataEvent(
                    ModuleDataEvent(ISmartAlarmIngestModuleFactory.moduleName, art_type, None))

                # Clean Up
                os.remove(lcl_setting_path)

                progressBar.progress(file_count)

            # MQTT Files
            for file in mqtt_files:

                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                self.log(Level.INFO, "Processing file: " + file.getName())
                file_count += 1

                # Make an artifact on the blackboard.
                # Set the DB file as an "interesting file" : TSK_INTERESTING_FILE_HIT is a generic type of
                # artifact.  Refer to the developer docs for other examples.
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                                          ISmartAlarmIngestModuleFactory.moduleName, "iSmartAlarm")
                art.addAttribute(att)
                progressBar.progress(file_count)

            # REG_KEY File
            for file in reg_file:

                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                self.log(Level.INFO, "Processing file: " + file.getName())
                file_count += 1

                # Make an artifact on the blackboard.
                # Set the DB file as an "interesting file" : TSK_INTERESTING_FILE_HIT is a generic type of
                # artifact.  Refer to the developer docs for other examples.
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                                          ISmartAlarmIngestModuleFactory.moduleName, "iSmartAlarm")
                art.addAttribute(att)
                progressBar.progress(file_count)

        # FINISHED!
        # Post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                              "iSmartAlarm Analysis", "Found %d files" % file_count)
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK

    def ismart_artifacts(self, case):
        try:
            self.log(Level.INFO, "Begin Create New Artifacts ==> ESC_IOT_ISMARTALARM")
            case.addArtifactType("ESC_IOT_ISMARTALARM", "iSmart Alarm Events")
        except:
            self.log(Level.INFO, "Artifacts Creation Error, artifact ESC_IOT_ISMARTALARM exists.")

        # Add Custom attributes to blackboard
        # iSmartAlarm Specific Attributes
        try:
            case.addArtifactAttributeType("ESC_IOT_ISMART_EVENT_NAME",
                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                          "Event")
        except:
            self.log(Level.INFO, "Attributes Creation Error, ESC_IOT_ISMART_EVENT_NAME")
        try:
            case.addArtifactAttributeType("ESC_IOT_ISMART_EVENT_DATE",
                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME,
                                          "Event Timestamp")
        except:
            self.log(Level.INFO, "Attributes Creation Error, ESC_IOT_ISMART_EVENT_DATE")
        try:
            case.addArtifactAttributeType("ESC_IOT_ISMART_EVENT_TYPE",
                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                          "Event Type")
        except:
            self.log(Level.INFO, "Attributes Creation Error, ESC_IOT_ISMART_EVENT_TYPE ")
        try:
            case.addArtifactAttributeType("ESC_IOT_ISMART_EVENT_DEVICE",
                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                          "Device")
        except:
            self.log(Level.INFO, "Attributes Creation Error, ESC_IOT_ISMART_EVENT_DEVICE")
        try:
            case.addArtifactAttributeType("ESC_IOT_ISMART_EVENT_DEVICE_TYPE",
                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                          "Device Type")
        except:
            self.log(Level.INFO, "Attributes Creation Error, ESC_IOT_ISMART_EVENT_DEVICE_TYPE")


# Stores the settings that can be changed for each ingest job
# All fields in here must be serializable.  It will be written to disk.
# TODO: Rename this class
class ISmartAlarmIngestModuleSettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.parse_db = True
        self.parse_settings = True
        self.parse_logs = True
        self.parse_network = True

    def getVersionNumber(self):
        return serialVersionUID

    # TODO: Define getters and settings for data you want to store from UI
    def get_parse_db(self):
        return self.parse_db

    def set_parse_db(self, flag):
        self.parse_db = flag

    def get_parse_settings(self):
        return self.parse_settings

    def set_parse_settings(self, flag):
        self.parse_settings = flag

    def get_parse_logs(self):
        return self.parse_logs

    def set_parse_logs(self, flag):
        self.parse_logs = flag

    def get_parse_network(self):
        return self.parse_network

    def set_parse_network(self, flag):
        self.parse_network = flag

    def __str__(self):
        return "iSmart Alarm Parser - Settings: Parse_DB = {}, Parse_Settings = {}, Parse_Logs = {}, Parse_Network = {}".format(
            self.parse_db, self.parse_settings, self.parse_logs, self.parse_network)


# UI that is shown to user for each ingest job so they can configure the job.
# TODO: Rename this
class ISmartAlarmIngestModuleSettingsPanel(IngestModuleIngestJobSettingsPanel):
    # Note, we can't use a self.settings instance variable.
    # Rather, self.local_settings is used.
    # https://wiki.python.org/jython/UserGuide#javabean-properties
    # Jython Introspector generates a property - 'settings' on the basis
    # of getSettings() defined in this class. Since only getter function
    # is present, it creates a read-only 'settings' property. This auto-
    # generated read-only property overshadows the instance-variable -
    # 'settings'

    # We get passed in a previous version of the settings so that we can
    # prepopulate the UI
    # TODO: Update this for your UI
    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()

    # TODO: Update this for your UI
    def db_checkbox_event(self, event):
        if self.db_parse_checkbox.isSelected():
            self.local_settings.set_parse_db(True)
        else:
            self.local_settings.set_parse_db(False)

    def settings_checkbox_event(self, event):
        if self.settings_parse_checkbox.isSelected():
            self.local_settings.set_parse_settings(True)
        else:
            self.local_settings.set_parse_settings(False)

    def logs_checkbox_event(self, event):
        if self.logs_parse_checkbox.isSelected():
            self.local_settings.set_parse_logs(True)
        else:
            self.local_settings.set_parse_logs(False)

    def network_checkbox_event(self, event):
        if self.network_parse_checkbox.isSelected():
            self.local_settings.set_parse_network(True)
        else:
            self.local_settings.set_parse_network(False)

    # TODO: Update this for your UI
    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.db_parse_checkbox = JCheckBox("Parse Database Logs", actionPerformed=self.db_checkbox_event)
        self.add(self.db_parse_checkbox)
        self.settings_parse_checkbox = JCheckBox("Parse Setting Files", actionPerformed=self.settings_checkbox_event)
        self.add(self.settings_parse_checkbox)
        self.logs_parse_checkbox = JCheckBox("Parse Logs in Media Folder", actionPerformed=self.logs_checkbox_event)
        self.add(self.logs_parse_checkbox)
        self.network_parse_checkbox = JCheckBox("Parse Network Logs (filename has to be: ismart_diag.stream)",
                                                actionPerformed=self.network_checkbox_event)
        self.add(self.network_parse_checkbox)

    # TODO: Update this for your UI
    def customizeComponents(self):
        self.db_parse_checkbox.setSelected(self.local_settings.get_parse_db())
        self.settings_parse_checkbox.setSelected(self.local_settings.get_parse_settings())
        self.logs_parse_checkbox.setSelected(self.local_settings.get_parse_logs())
        self.network_parse_checkbox.setSelected(self.local_settings.get_parse_network())

    # Return the settings used
    def getSettings(self):
        return self.local_settings


