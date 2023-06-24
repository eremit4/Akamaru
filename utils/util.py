from os import mkdir
from os.path import isdir
from colorama import Fore
from datetime import datetime
from prettytable import PrettyTable


def get_sector_keywords(sector_name: str) -> list:
    """
    Choose the keywords by sector.
    :param sector_name: Sector name.
    :return: A list with the keywords.
    """
    if sector_name == "financial":
        return ["economic", "bank", "financial", "finance", "investment firms", "payment card"]
    if sector_name == "healthcare":
        return ["health", "healthcare", "hospital", "pharmaceutical", "medical", "disease", "medical", "COVID-19"]
    if sector_name == "ics":
        return ["ICS", "manufacturing", "manufacturers", "oil", "mining", "chemistry", "energy", "critical infrastructure", "nuclear", "petroleum", "semicondutor", "airline", "aerospace", "aviation", "engineering industries", "industrial control systems"]
    if sector_name == "defense":
        return ["military", "defense", "army"]
    if sector_name == "government":
        return ["government", "presidential election", "democratic", "diplomatic", "legal services", "political", "ministries", "judiciary", "policy"]
    if sector_name == "technology":
        return ["technology", "big tech", "high tech", "high-tech", "video game", "gaming", "internet service"]
    if sector_name == "telecom":
        return ["telecom", "telephony"]
    if sector_name == "education":
        return ["education", "college", "universit", "academic", "school", "educational"]
    if sector_name == "retail":
        return ["retail", "commerce", "restaurant"]
    if sector_name == "media":
        return ["media sector", "television", "media outlets", "journalist", "opposition bloggers", "regional news", "high-profile personalities", "social media"]
    if sector_name == "law":
        return ["law firms", "legal services"]
    if sector_name == "tourism":
        return ["hospitality", "tourism", "travel", "hotel"]


def check_sector_blacklist(desc: str, sector: str) -> str:
    """
    Checks if some blacklisted terms appear in the description and removes them.
    :param desc: Description of the group.
    :param sector: Sector name.
    :return: The new description without the blacklisted terms.
    """
    blacklist = {
        "financial": [""],
        "healthcare": [""],
        "ics": ["cryptocurrency-mining"],
        "defense": [""],
        "government": [""],
        "technology": [""],
        "education": [""],
        "media": [""],
        "law": [""],
        "tourism": [""]
    }
    for keyword in blacklist.get(sector):
        desc = desc.replace(keyword, "")
    return desc


def check_group_in_groups(group: str, groups: list) -> dict:
    """
    Checks if the group typed by user exists in groups collected.
    :param group: Group name.
    :param groups: Groups collected.
    :return: A dict with information about a group.
    """
    for group_ in groups:
        if group.lower() in group_["name"].lower():
            return group_
    return {}


def create_csv_report(mitre=None, sentinel=None, ttp=None) -> None:
    """
    Create a CSV report.
    :param mitre: Results from MITRE ATT&CK.
    :param sentinel: Results from SentinelOne.
    :param ttp: A boolean value that indicates if the flag <ttp> was provided.
    :return: None.
    """
    print(f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Preparing the report")
    report_name = f"akamaru_report_{datetime.now().strftime('%d-%m-%Y')}.csv"
    if not isdir("./akamaru_output"):
        mkdir("./akamaru_output")
    report_file = open(file=f"./akamaru_output/{report_name}", mode="w")
    # writing the header
    report_file.write(f"Group;Source;Url;Groups Related;Softwares\n")
    # writing other lines
    if mitre is not None:
        if mitre.get("mitre_groups"):
            for data in mitre.get("mitre_groups").items():
                if ttp is not None:
                    softwares = str(data[1].get("softwares")).replace("[", "").replace("]", "").replace("'", "").strip()
                    report_file.write(f"{data[1].get('name').strip()};MITRE ATT&CK;{data[1].get('navigator_url').strip()};{data[1].get('relations').strip()};{softwares}\n")
                else:
                    report_file.write(f"{data[1].get('name').strip()};MITRE ATT&CK;{data[1].get('navigator_url').strip()};{data[1].get('relations').strip()};None\n")
        elif mitre.get("softwares"):
            softwares = str(mitre.get("softwares")).replace("[", "").replace("]", "").replace("'", "").strip()
            report_file.write(f"{mitre.get('name')};MITRE ATT&CK;{mitre.get('url')};{mitre.get('relations')};{softwares}\n")

    if sentinel is not None:
        if sentinel.get("groups"):
            for group in sentinel.get("groups"):
                report_file.write(f"{str(group.get('name').strip())};SentinelOne;{group.get('url').strip()};None;None\n")

    report_file.close()
    print(f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] The {Fore.MAGENTA}{report_name}{Fore.WHITE} report was successfully created and is located in the {Fore.MAGENTA}output{Fore.WHITE} directory")


def print_supported_sectors() -> None:
    """
    Shows on the screen which sectors are supported
    :return: None
    """
    sectors_table = PrettyTable()
    sectors_table.field_names = ["Supported Sectors"]
    for sector in sorted(["financial", "healthcare", "ics", "defense", "government", "technology", "education", "media", "law", "tourism"]):
        sectors_table.add_row([f"{Fore.WHITE}{sector}{Fore.LIGHTBLUE_EX}"])
    print(f"{Fore.LIGHTBLUE_EX}{sectors_table.get_string(fields=['Supported Sectors'])}")

