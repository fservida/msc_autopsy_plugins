# File shared by all python plugins for autopsy
# Creates if needed the Artifact and related attributes to store a username along with a password or an auth token
# (eg. oauth2 token)

from java.util.logging import Level
from org.sleuthkit.datamodel import BlackboardAttribute


def esc_generic_artifacts(self, case):

    # Artifacts
    try:
        self.log(Level.INFO, "Begin Create New Artifacts ==> ESC_GENERIC_LOGIN")
        case.addArtifactType("ESC_GENERIC_LOGIN", "User Passwords & Tokens")
    except:
        self.log(Level.INFO, "Artifacts Creation Error, artifact ESC_GENERIC_LOGIN exists.")

    # Attributes
    try:
        case.addArtifactAttributeType("ESC_GENERIC_LOGIN_USERNAME",
                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                      "Username")
    except:
        self.log(Level.INFO, "Attributes Creation Error, ESC_GENERIC_LOGIN_USERNAME")

    try:
        case.addArtifactAttributeType("ESC_GENERIC_LOGIN_SECRET",
                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                      "Secret")
    except:
        self.log(Level.INFO, "Attributes Creation Error, ESC_GENERIC_LOGIN_SECRET")

    try:
        case.addArtifactAttributeType("ESC_GENERIC_LOGIN_SECRET_TYPE",
                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                      "Secret Type")
        # Should be one of (Password, Oauth2 Token, Unkown Token)
    except:
        self.log(Level.INFO, "Attributes Creation Error, ESC_GENERIC_LOGIN_SECRET_TYPE")

    try:
        case.addArtifactAttributeType("ESC_GENERIC_LOGIN_REMARKS",
                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                      "Remarks")
    except:
        self.log(Level.INFO, "Attributes Creation Error, ESC_GENERIC_LOGIN_REMARKS")

    try:
        case.addArtifactAttributeType("ESC_GENERIC_LOGIN_SERVICE",
                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                      "Service")
    except:
        self.log(Level.INFO, "Attributes Creation Error, ESC_GENERIC_LOGIN_SERVICE")
