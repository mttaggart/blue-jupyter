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
    def __init__(self, soup):
        super().__init__(soup)
        self.command_line = SysmonEvent.extract_event_data(soup, "data[name='CommandLine']")
        self.parent_command_line = SysmonEvent.extract_event_data(soup, "data[name='ParentCommandLine']")
        self.parent_image = SysmonEvent.extract_event_data(soup, "data[name='ParentImage']")
        self.integrity_levels = SysmonEvent.extract_event_data(soup, "data[name='IntegrityLevel']")

class NetworkConnect(SysmonEvent):
    def __init__(self, soup):
        super().__init__(soup)
        self.src_ip = SysmonEvent.extract_event_data(soup, "data[name='SourceIp']")
        self.dest_ip = SysmonEvent.extract_event_data(soup, "data[name='DestinationIp']")
        self.src_port = SysmonEvent.extract_event_data(soup, "data[name='SourcePort']")
        self.dest_port = SysmonEvent.extract_event_data(soup, "data[name='DestinationPort']")
        self.integrity_levels = SysmonEvent.extract_event_data(soup, "data[name='IntegrityLevel']")


EVENT_TYPES = {
    "1": ProcessCreate,
    "3": NetworkConnect
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