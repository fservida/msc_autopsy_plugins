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
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec

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
from org.sleuthkit.datamodel import TskData

import os
from subprocess import Popen, PIPE

import json

from esc_generic import esc_generic_artifacts


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class QBeeIngestModuleFactory(IngestModuleFactoryAdapter):
    moduleName = "QBee Analysis"

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
        return QBeeIngestModuleSettings()

    # TODO: Keep enabled only if you need ingest job-specific settings UI
    def hasIngestJobSettingsPanel(self):
        return True

    # TODO: Update class names to ones that you create below
    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, QBeeIngestModuleSettings):
            raise IllegalArgumentException(
                "Expected settings argument to be instance of QBeeIngestModuleSettings")
        self.settings = settings
        return QBeeIngestModuleSettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return QBeeIngestModule(self.settings)


# Data Source-level ingest module.  One gets created per data source.
class QBeeIngestModule(DataSourceIngestModule):
    _logger = Logger.getLogger(QBeeIngestModuleFactory.moduleName)

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

        # Generic Login Artifacts & Attributes
        esc_generic_artifacts(self, case)

        # Search decrypter exe and load path
        self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crypto_dec/crypto_dec.exe")
        if not os.path.exists(self.path_to_exe):
            raise IngestModuleException("EXE was not found in module folder")

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

        swisscom_settings_file = fileManager.findFiles(dataSource,
                                                       "com.swisscom.internetbox_preferences.xml") if self.local_settings.get_parse_settings() else []
        qbee_settings_file = fileManager.findFiles(dataSource,
                                                   "com.vestiacom.qbeecamera_preferences.xml") if self.local_settings.get_parse_settings() else []

        num_files = len(qbee_settings_file) + len(swisscom_settings_file)

        self.log(Level.INFO, "found " + str(num_files) + " files")
        progressBar.switchToDeterminate(num_files)
        file_count = 0

        # Settings
        tmp_dir = Case.getCurrentCase().getTempDirectory()
        out_dir = Case.getCurrentCase().getModuleDirectory()
        if self.local_settings.get_parse_settings():
            # Settings File for Qbee App
            for file in qbee_settings_file:

                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                self.log(Level.INFO, "Processing file: " + file.getName())
                file_count += 1


                # Write to file (any way to contour this?)
                lcl_setting_path = os.path.join(tmp_dir, str(file.getId()) + ".xml")
                ContentUtils.writeToFile(file, File(lcl_setting_path))

                out_file_name = file.getName() + "_decrypted.json"
                dest_json_path = os.path.join(out_dir, out_file_name)
                pipe = Popen([self.path_to_exe, lcl_setting_path, dest_json_path], stdout=PIPE, stderr=PIPE)

                out_text = pipe.communicate()[0]
                self.log(Level.INFO, "Output from run is ==> " + out_text)

                with open(dest_json_path) as json_file:
                    settings_clear = json.load(json_file)

                self.log(Level.INFO, "Settings: " + str(settings_clear))

                try:
                    settings_clear = settings_clear['decrypted_settings'][0]
                except KeyError:
                    raise KeyError("JSON File format unknown")
                except IndexError:
                    self.log(Level.INFO, "Error: No AES key candidates found while decrypting settings file.")
                    continue

                json_info = os.stat(dest_json_path)
                print json_info.st_mtime

                encoding = TskData.EncodingType.valueOf(0)
                dest_json_rel_path = os.path.relpath(dest_json_path, Case.getCurrentCase().getCaseDirectory())
                json_file = fileManager.addDerivedFile(out_file_name, dest_json_rel_path, int(json_info.st_size),
                                                       int(json_info.st_ctime), int(json_info.st_ctime),
                                                       int(json_info.st_atime), int(json_info.st_mtime), True, file,
                                                       "QBee Module", "Qbee Module", "0.1", "", encoding)

                art_type_id = case.getArtifactTypeID("ESC_GENERIC_LOGIN")
                art_type = case.getArtifactType("ESC_GENERIC_LOGIN")

                # Make an artifact on the blackboard.
                # Set the DB file as an "interesting file" : TSK_INTERESTING_FILE_HIT is a generic type of
                # artifact.  Refer to the developer docs for other examples.
                art = json_file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                                          QBeeIngestModuleFactory.moduleName, "QBee")
                art.addAttribute(att)

                # Artifact
                art = file.newArtifact(art_type_id)
                # Attributes
                att_login_username_id = case.getAttributeType("ESC_GENERIC_LOGIN_USERNAME")
                att_login_secret_id = case.getAttributeType("ESC_GENERIC_LOGIN_SECRET")
                att_login_secret_type_id = case.getAttributeType("ESC_GENERIC_LOGIN_SECRET_TYPE")
                att_login_service_id = case.getAttributeType("ESC_GENERIC_LOGIN_SERVICE")

                att_login_username = BlackboardAttribute(att_login_username_id,
                                                         QBeeIngestModuleFactory.moduleName, settings_clear['qbeeUser'])
                att_login_secret = BlackboardAttribute(att_login_secret_id,
                                                       QBeeIngestModuleFactory.moduleName,
                                                       settings_clear['qbeePassword'])
                att_login_secret_type = BlackboardAttribute(att_login_secret_type_id,
                                                            QBeeIngestModuleFactory.moduleName, "Password")
                att_login_service = BlackboardAttribute(att_login_service_id,
                                                        QBeeIngestModuleFactory.moduleName, "QBee")

                art.addAttribute(att_login_username)
                art.addAttribute(att_login_secret)
                art.addAttribute(att_login_secret_type)
                art.addAttribute(att_login_service)

                IngestServices.getInstance().fireModuleDataEvent(
                    ModuleDataEvent(QBeeIngestModuleFactory.moduleName, art_type, None))

                progressBar.progress(file_count)

            # Settings File for Swisscom Home App
            for file in swisscom_settings_file:

                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                self.log(Level.INFO, "Processing file: " + file.getName())
                file_count += 1

                # Write to file (any way to contour this?)
                lcl_setting_path = os.path.join(tmp_dir, str(file.getId()) + ".xml")
                ContentUtils.writeToFile(file, File(lcl_setting_path))

                out_file_name = file.getName() + "_decrypted.json"
                dest_json_path = os.path.join(out_dir, out_file_name)
                pipe = Popen([self.path_to_exe, lcl_setting_path, dest_json_path], stdout=PIPE, stderr=PIPE)

                out_text = pipe.communicate()[0]
                self.log(Level.INFO, "Output from run is ==> " + out_text)

                with open(dest_json_path) as json_file:
                    settings_clear = json.load(json_file)

                self.log(Level.INFO, "Settings: " + str(settings_clear))

                try:
                    settings_clear = settings_clear['decrypted_settings'][0]
                except KeyError:
                    raise KeyError("JSON File format unknown")
                except IndexError:
                    self.log(Level.INFO, "Error: No AES key candidates found while decrypting settings file.")
                    continue

                json_info = os.stat(dest_json_path)
                print json_info.st_mtime

                encoding = TskData.EncodingType.valueOf(0)
                dest_json_rel_path = os.path.relpath(dest_json_path, Case.getCurrentCase().getCaseDirectory())
                json_file = fileManager.addDerivedFile(out_file_name, dest_json_rel_path, int(json_info.st_size),
                                                       int(json_info.st_ctime), int(json_info.st_ctime),
                                                       int(json_info.st_atime), int(json_info.st_mtime), True, file,
                                                       "QBee Module", "Qbee Module", "0.1", "", encoding)

                # Make an artifact on the blackboard.
                # Set the DB file as an "interesting file" : TSK_INTERESTING_FILE_HIT is a generic type of
                # artifact.  Refer to the developer docs for other examples.
                art = json_file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                                          QBeeIngestModuleFactory.moduleName, "Swisscom Home App")
                art.addAttribute(att)

                progressBar.progress(file_count)

        # FINISHED!
        # Post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                              "QBee Analysis", "Found %d files" % file_count)
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK


# Stores the settings that can be changed for each ingest job
# All fields in here must be serializable.  It will be written to disk.
# TODO: Rename this class
class QBeeIngestModuleSettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.parse_settings = True

    def getVersionNumber(self):
        return serialVersionUID

    # TODO: Define getters and settings for data you want to store from UI

    def get_parse_settings(self):
        return self.parse_settings

    def set_parse_settings(self, flag):
        self.parse_settings = flag

    def __str__(self):
        return "QBee Parser - Settings: Parse_Settings = {}".format(self.parse_settings)


# UI that is shown to user for each ingest job so they can configure the job.
# TODO: Rename this
class QBeeIngestModuleSettingsPanel(IngestModuleIngestJobSettingsPanel):
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
    def settings_checkbox_event(self, event):
        if self.settings_parse_checkbox.isSelected():
            self.local_settings.set_parse_settings(True)
        else:
            self.local_settings.set_parse_settings(False)

    # TODO: Update this for your UI
    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.settings_parse_checkbox = JCheckBox("Parse Setting Files", actionPerformed=self.settings_checkbox_event)
        self.add(self.settings_parse_checkbox)

    # TODO: Update this for your UI
    def customizeComponents(self):
        self.settings_parse_checkbox.setSelected(self.local_settings.get_parse_settings())

    # Return the settings used
    def getSettings(self):
        return self.local_settings
