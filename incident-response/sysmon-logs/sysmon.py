from Evtx import Evtx
from bs4 import BeautifulSoup

class SysmonEvent:

    @staticmethod
    def extract_event_data(soup, query):
        """
        Attempts to select event data from the eventdata soup component
        """
        try:
            return soup.eventdata.select_one(query).text
        except:
            return ""    

    def __init__(self, soup):
        self.soup = soup
        self.user_id = soup.security.attrs["userid"]
        self.event_id = soup.eventid.text
        
        self.time_created = soup.timecreated.attrs["systemtime"]
        self.pid = SysmonEvent.extract_event_data(soup, "data[name='ProcessId']")
        self.image = SysmonEvent.extract_event_data(soup, "data[name='Image']")
        self.user = SysmonEvent.extract_event_data(soup, "data[name='User']")

class ProcessCreate(SysmonEvent):
    """
    Event ID 1
    """
    def __init__(self, soup):
        super().__init__(soup)
        self.hashes = SysmonEvent.extract_event_data(soup, "data[name='Hashes']")
        self.command_line = SysmonEvent.extract_event_data(soup, "data[name='CommandLine']")
        self.parent_command_line = SysmonEvent.extract_event_data(soup, "data[name='ParentCommandLine']")
        self.parent_image = SysmonEvent.extract_event_data(soup, "data[name='ParentImage']")
        self.integrity_levels = SysmonEvent.extract_event_data(soup, "data[name='IntegrityLevel']")

class FileCreationTimeChanged(SysmonEvent):
    """
    Event ID 2
    """
    def __init__(self, soup):
        super().__init__(soup)
        self.target_filename = SysmonEvent.extract_event_data(soup, "data[name='TargetFilename']")
        self.creation_utc_time = SysmonEvent.extract_event_data(soup, "data[name='CreationUtcTime']")
        self.previous_creation_utc_time = SysmonEvent.extract_event_data(soup, "data[name='PreviousCreationUtcTime']")        

class NetworkConnect(SysmonEvent):
    """
    Event ID 3
    """
    def __init__(self, soup):
        super().__init__(soup)
        self.src_ip = SysmonEvent.extract_event_data(soup, "data[name='SourceIp']")
        self.dest_ip = SysmonEvent.extract_event_data(soup, "data[name='DestinationIp']")
        self.src_port = SysmonEvent.extract_event_data(soup, "data[name='SourcePort']")
        self.dest_port = SysmonEvent.extract_event_data(soup, "data[name='DestinationPort']")
        self.integrity_levels = SysmonEvent.extract_event_data(soup, "data[name='IntegrityLevel']")

class DriverLoaded(SysmonEvent):
    """
    Event ID 6
    """
    def __init__(self, soup):
        super().__init__(soup)
        self.image_loaded = SysmonEvent.extract_event_data(soup, "data[name='ImageLoaded']")
        self.signed = SysmonEvent.extract_event_data(soup, "data[name='Signed']")
        self.hashes = SysmonEvent.extract_event_data(soup, "data[name='Hashes']")
        self.signature = SysmonEvent.extract_event_data(soup, "data[name='Signature']")
        self.signature_status = SysmonEvent.extract_event_data(soup, "data[name='SignatureStatus']")

class ImageLoaded(SysmonEvent):
    """
    Event ID 7
    """
    def __init__(self, soup):
        super().__init__(soup)
        self.image_loaded = SysmonEvent.extract_event_data(soup, "data[name='ImageLoaded']")
        self.signed = SysmonEvent.extract_event_data(soup, "data[name='Signed']")
        self.hashes = SysmonEvent.extract_event_data(soup, "data[name='Hashes']")
        self.signature = SysmonEvent.extract_event_data(soup, "data[name='Signature']")
        self.signature_status = SysmonEvent.extract_event_data(soup, "data[name='SignatureStatus']")

class CreateRemoteThread(SysmonEvent):
    """
    Event ID 8
    """
    def __init__(self, soup):
        super().__init__(soup)
        self.source_pid = SysmonEvent.extract_event_data(soup, "data[name='SourceProcessId']")
        self.target_pid = SysmonEvent.extract_event_data(soup, "data[name='TargetProcessId']")
        self.source_image = SysmonEvent.extract_event_data(soup, "data[name='SourceImage']")
        self.target_image = SysmonEvent.extract_event_data(soup, "data[name='TargetImage']")
        self.new_thread_id = SysmonEvent.extract_event_data(soup, "data[name='NewThreadId']")

class RawAccessRead(SysmonEvent):
    """
    Event ID 9
    """
    def __init__(self, soup):
        super().__init__(soup)
        self.device = SysmonEvent.extract_event_data(soup, "data[name='Device']")

class FileCreate(SysmonEvent):
    """
    Event ID 11
    """
    def __init__(self, soup):
        super().__init__(soup)
        self.target_filename = SysmonEvent.extract_event_data(soup, "data[name='TargetFilename']")

class RegistryCreateDelete(SysmonEvent):
    """
    Event ID 12
    """
    def __init__(self, soup):
        super().__init__(soup)
        self.target_object = SysmonEvent.extract_event_data(soup, "data[name='TargetObject']")

class RegistryValueSet(SysmonEvent):
    """
    Event ID 13
    """
    def __init__(self, soup):
        super().__init__(soup)
        self.target_object = SysmonEvent.extract_event_data(soup, "data[name='TargetObject']")
        self.details = SysmonEvent.extract_event_data(soup, "data[name='Details']")

class RegistryKeyValueRename(SysmonEvent):
    """
    Event ID 14
    """
    def __init__(self, soup):
        super().__init__(soup)
        self.target_object = SysmonEvent.extract_event_data(soup, "data[name='TargetObject']")
        self.new_name = SysmonEvent.extract_event_data(soup, "data[name='NewName']")

class PipeEvent(SysmonEvent):
    """
    Event ID 17, 18
    """
    def __init__(self, soup):
        super().__init__(soup)
        self.pipe_name = SysmonEvent.extract_event_data(soup, "data[name='PipeName']")

class WmiEventFilter(SysmonEvent):
    """
    Event ID 19
    """
    def __init__(self, soup):
        super().__init__(soup)
        self.event_namespace = SysmonEvent.extract_event_data(soup, "data[name='EventNamespace']")
        self.filter_name = SysmonEvent.extract_event_data(soup, "data[name='Name']")
        self.query = SysmonEvent.extract_event_data(soup, "data[name='Query']")

class DNSEvent(SysmonEvent):
    """
    Event ID 22
    """
    def __init__(self, soup):
        super().__init__(soup)
        self.query_name = SysmonEvent.extract_event_data(soup, "data[name='QueryName']")
        self.query_results = SysmonEvent.extract_event_data(soup, "data[name='QueryResults']")

class ProcessTampering(SysmonEvent):
    """
    Event ID 25
    """
    def __init__(self, soup):
        super().__init__(soup)
        self.type = SysmonEvent.extract_event_data(soup, "data[name='Type']")


EVENT_TYPES = {
    "1": ProcessCreate,
    "2": FileCreationTimeChanged,
    "3": NetworkConnect,
    "6": DriverLoaded,
    "7": ImageLoaded,
    "8": CreateRemoteThread,
    "9": RawAccessRead,
    "11": FileCreate,
    "12": RegistryCreateDelete,
    "13": RegistryValueSet,
    "14": RegistryKeyValueRename,
    "17": PipeEvent,
    "18": PipeEvent,
    "19": WmiEventFilter,
    "22": DNSEvent,
    "25": ProcessTampering
}

def load_event_xml(file_path):
    """
    Loads raw XML from Evtx file
    """
    with Evtx.Evtx(file_path) as f:
        records_xml = [f.xml() for f in f.records()]
        return records_xml

def build_event(raw_xml):
    soup = BeautifulSoup(raw_xml, "lxml")
    id = soup.eventid.text
    if id in EVENT_TYPES:
        constructor = EVENT_TYPES[id]
        return constructor(soup)
    return SysmonEvent(soup)

def load_events(file_path):
    """
    Generate and return a list of SysmonEvents
    """
    records_xml = load_event_xml(file_path)
    return [build_event(r)  for r in records_xml]