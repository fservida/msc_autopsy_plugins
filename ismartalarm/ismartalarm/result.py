from datetime import datetime


class ISmartDevice(object):
    def __init__(self, name, sn, device_type):
        self.name = name
        self.device_sn = sn
        self.device_type = device_type

    def __hash__(self):
        return hash(self.device_sn)

    def __str__(self):
        return "ISmartDevice: {} - SN={}".format(self.name, self.device_sn)

    __repr__ = __str__

    def __eq__(self, other):
        if isinstance(other, ISmartDevice):
            return self.device_sn == other.device_sn
        elif isinstance(other, str):
            return self.device_sn == other
        else:
            raise TypeError("Comparison of ISmartDevice and object of unsupported type")


class ISmartEvent(object):
    def __init__(self):
        self.__timestamp = None
        self.name = None
        self.event_type = None
        self.device = None

    @property
    def timestamp(self):
        return self.__timestamp

    @timestamp.setter
    def timestamp(self, timestamp):
        timestamp = int(timestamp) if len(str(timestamp)) == 10 else int(timestamp) // 1000
        self.__timestamp = datetime.fromtimestamp(timestamp)

    def __str__(self):
        return "ISmartEvent: {} - {} - {} - [{}]".format(self.name, self.event_type,
                                                         self.timestamp.strftime("%Y-%m-%d %H:%M"), self.device)

    __repr__ = __str__

    def __eq__(self, other):
        if not isinstance(other, ISmartEvent):
            raise TypeError("Comparison of ISmartDevice and object of unsupported type")
        return self.__timestamp == other.__timestamp

    def __gt__(self, other):
        if not isinstance(other, ISmartEvent):
            raise TypeError("Comparison of ISmartDevice and object of unsupported type")
        return self.__timestamp > other.__timestamp

    def __ge__(self, other):
        if not isinstance(other, ISmartEvent):
            raise TypeError("Comparison of ISmartDevice and object of unsupported type")
        return self.__timestamp >= other.__timestamp


class ISmartEventDB(ISmartEvent):
    cube_status = {1: "Cube Offline", 2: "Cube Online"}
    alarms = {1: "Contact Sensor Alarm", 2: "Motion Sensor Alarm"}
    log_types = {
        5: "Cube Status",
        2: "Profile Change",
        1: "Alarm"
    }

    remote_tag_actions = {
        0: "HOME",
        1: "ARM",
        2: "DISARM",
        4: "HOME",
        5: "LEFT HOME",
    }

    actions = {
        1: "Contact Sensor Open",
        2: "Contact Sensor Closed",
        3: "Contact Sensor Open",
        4: "Contact Sensor Closed",
        5: "Motion Detected",
        6: "Low Battery Power",
        7: "Nominal Battery Power",
        8: "Smoke Alarm",
        9: "tv_5_13_notrigger",
        10: "tv_5_13_online",
        11: "act3_7_disconnected",
        12: "timer_task_open",
        13: "timer_task_close",
        14: "Device Added",
        15: "Device Deleted",
    }

    def __init__(self):
        """
        Initializes the event
        :param ipu: serial number of the cube interested by the modification
        """
        ISmartEvent.__init__(self)

    def __parse_cube_status(self, row):
        pass

    def __parse_alarms(self, row):
        pass

    def __parse_actions(self, row):
        pass

    def parse_ipu(self, row, events):
        """
        Parse a TB_IPUDAiry row (Actions)
        :param row: row from sqlite db
        :param events
        :type events: ISmartEvents
        :return: None, fill event with infos
        """

        self.timestamp = row[0]

        log_type = row[3]
        self.event_type = self.log_types.get(int(log_type), "Unknown Event Type")  # [int(log_type)]

        if log_type == 1:
            # Alarm
            self.name = self.alarms.get(int(row[1]), "Unknown Alarm")
            device = str(row[4])
            device_type = "Contact Sensor" if int(row[1]) == 1 else "Motion Detector"

        elif log_type == 2:
            # Profile Change
            self.name = row[-1]
            device = str(row[5])
            device_type = "Remote Tag or Smartphone"

        elif log_type == 5:
            # Cube Status
            self.name = self.cube_status.get(int(row[1]), "Unknown Cube Status")
            device = str(row[2])  # Device is IPU
            device_type = "Base Station"

        else:
            raise ValueError("Unknown Log Type")

        if device not in events.devices:
            device = ISmartDevice(device, device, device_type)
            events.devices[device] = device
        else:
            device = events.devices[device]
        self.device = device

    def parse_sensors(self, row, events):
        """
        Parse a TB_IPUDAiry row (Actions)
        :param row: row from sqlite db (7 elements)
        :param events
        :type events: ISmartEvents
        :return: None, fill event with infos
        """

        self.timestamp = row[0]

        self.event_type = "Sensor Info"

        log_type = str(row[6])
        if log_type == "1":
            # Remote Tag
            self.name = self.remote_tag_actions.get(int(row[2]), "Unknown Action")
            device = str(row[5])
            device_type = "Remote Tag"
            self.event_type = "?User Info?"
        else:
            action = int(row[2])
            device = str(row[1])
            try:
                self.name = self.actions.get(action, "Unknown")
                if str(row[3]) == "0":
                    # Model == 0 --> Action 8 is a test of some sort
                    self.name = "Unknown Device Test (Likely Smoke Detector)"
                device_type = self.__get_device_type(action)
            except KeyError:
                raise ValueError("Unknown Action Type")

        if device not in events.devices:
            device = ISmartDevice(device, device, device_type)
            events.devices[device] = device
        else:
            device = events.devices[device]
            if device.device_type == "Unknown":
                device.device_type = device_type
            device = events.devices[device]
        self.device = device

    @staticmethod
    def __get_device_type(action):
        device_types = {
            "Contact Sensor": (1, 2, 3, 4),
            "Motion Detector": (5,),
            "Smoke Detector": (8,),
            "Unknown": (6, 7, 9, 10, 11, 12, 13, 14, 15)
        }

        for device_type, actions in device_types.items():
            if action in actions:
                return device_type
        return "Unknown"


if __name__ == '__main__':
    from database import ISmartAlarmDB
    from pprint import pprint

    class ISmartEvents(object):
        def __init__(self, db):
            self.events = []
            self.devices = {}
            self.db = ISmartAlarmDB(db)
            self.__parse_actions()
            self.__parse_sensors()

        def __parse_actions(self):
            actions = self.db.parse_actions()
            for action in actions:
                event = ISmartEventDB()
                event.parse_ipu(action, self)
                self.events.append(event)

        def __parse_sensors(self):
            sensors = self.db.parse_sensors()
            for sensor_log in sensors:
                event = ISmartEventDB()
                event.parse_sensors(sensor_log, self)
                self.events.append(event)

        def __iter__(self):
            for event in self.events:
                yield event

    ismart = ISmartEvents("../data/iSmartAlarm_DFRWS.DB")
    pprint(ismart.events)


