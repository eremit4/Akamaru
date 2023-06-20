from tqdm import tqdm
from time import sleep
from requests import get
from colorama import Fore
from bs4 import BeautifulSoup
from traceback import format_exc
from prettytable import PrettyTable
from utils.util import get_sector_keywords, check_group_in_groups, check_sector_blacklist


def get_elements_from_mitre_groups_page() -> BeautifulSoup:
    """
    Gets the HTML elements from MITRE ATT&CK Groups page.
    :return: The Beautifulsoup object to be parser.
    """
    response = get(url="https://attack.mitre.org/groups/",
                   headers={
                       "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0",
                       "Accept": "*/*",
                       "Accept-Language": "pt - BR, pt;q = 0.8, en - US;q = 0.5, en;q = 0.3",
                       "Connection": "keep-alive",
                       "Upgrade-Insecure-Requests": "1"})
    if response.status_code == 200:
        return BeautifulSoup(response.content, "html.parser")


def get_ttps_from_mitre_by_group_id(group_id: str) -> BeautifulSoup:
    """
    Gets the HTML elements from MITRE ATT&CK Groups by group ID.
    :param group_id: The group ID from MITRE.
    :return: The Beautifulsoup object to be parser.
    """
    response = get(url=f"https://attack.mitre.org/groups/{group_id}",
                   headers={
                       "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0",
                       "Accept": "*/*",
                       "Accept-Language": "pt - BR, pt;q = 0.8, en - US;q = 0.5, en;q = 0.3",
                       "Connection": "keep-alive",
                       "Upgrade-Insecure-Requests": "1"})
    if response.status_code == 200:
        return BeautifulSoup(response.content, "html.parser")


def get_technique_from_mitre(tech_id: str, sub_tech_id=None) -> BeautifulSoup:
    """
    Gets the HTML elements of from Mitre ATT&CK Technique page by Technique ID.
    :param tech_id: The Technique ID from MITRE.
    :param sub_tech_id: The Sub-Technique ID from MITRE.
    :return: The Beautifulsoup object to be parser.
    """
    if sub_tech_id is not None:
        path = f"{tech_id}/{sub_tech_id}"
    else:
        path = tech_id
    response = get(url=f"https://attack.mitre.org/techniques/{path}",
                   headers={
                       "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0",
                       "Accept": "*/*",
                       "Accept-Language": "pt - BR, pt;q = 0.8, en - US;q = 0.5, en;q = 0.3",
                       "Connection": "keep-alive",
                       "Upgrade-Insecure-Requests": "1"})
    if response.status_code == 200:
        return BeautifulSoup(response.content, "html.parser")


def mitre_groups_parser(sector=None) -> list:
    """
    Parses the Beautifulsoup object and extract group information from MITRE ATT&CK.
    :param sector: The name of the sector of interest.
    :return: A dict of collected information.
    """
    soup, groups = get_elements_from_mitre_groups_page(), list()
    try:
        for item in tqdm(iterable=soup.find_all("tr")[1:],
                         desc=f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Collecting relevant groups from MITRE ATT&CK{Fore.BLUE}",
                         bar_format="{l_bar}{bar:10}"):
            groups_raw = item.get_text().strip().split("\n")
            mitre_group_id, mitre_group_name = groups_raw[0].strip(), groups_raw[3].strip()
            if groups_raw[6] != "":
                mitre_associated_groups, mitre_group_desc = groups_raw[6].strip(), groups_raw[9].strip()
            else:
                mitre_associated_groups, mitre_group_desc = "None", groups_raw[8]
            group_data = {
                "name": mitre_group_name,
                "mitre_id": mitre_group_id,
                "url": f"https://attack.mitre.org/groups/{mitre_group_id}",
                "relations": mitre_associated_groups,
                "description": mitre_group_desc
            }
            if sector is not None:
                for keyword_ in get_sector_keywords(sector_name=sector):
                    mitre_group_desc = check_sector_blacklist(desc=mitre_group_desc, sector=sector)
                    if sector is not None and keyword_ in mitre_group_desc and group_data not in groups:
                        groups.append(group_data)
            else:
                groups.append(group_data)
            sleep(0.002)
        return groups
    except AttributeError:
        return []


def get_softwares_used_from_mitre(group_id: str) -> list:
    """
    Gets the softwares used by a specific group on MITRE ATT&CK.
    :param group_id: MITRE Group ID.
    :return: A list with the softwares used.
    """
    soup, softwares = get_ttps_from_mitre_by_group_id(group_id=group_id), list()
    for a_tag in tqdm(iterable=soup.find_all("a")[1:],
                      desc=f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Collecting Softwares Used{Fore.BLUE}",
                      bar_format="{l_bar}{bar:10}"):
        if "/software/S" in a_tag.attrs["href"] and a_tag.attrs["href"].split("/")[2] != a_tag.get_text():
            softwares.append(a_tag.get_text())
    return list(set(softwares))


def get_mitre_navigator_url(group_id: str) -> dict:
    """
    Gets the MITRE ATT&CK Navigator URL by group.
    :param group_id: ID from threat group on MITRE ATT&CK.
    :return: A dict with the MITRE ATT&CK Navigator URL and content json.
    """
    soup = get_ttps_from_mitre_by_group_id(group_id=group_id)
    for a_tag in soup.find_all("a", {"class": "dropdown-item"}):
        if "layer.json" in a_tag.attrs["href"]:
            return {
                "matrix": f"https://mitre-attack.github.io/attack-navigator//#layerURL=https://attack.mitre.org/{a_tag.attrs['href']}",
                "json": f"https://attack.mitre.org/{a_tag.attrs['href']}"
            }


def print_mitre_groups_table(groups_from_mitre: list, columns=None) -> None:
    """
    Shows in the screen a table with groups collected from MITRE ATT&CK.
    :param groups_from_mitre: MITRE ATT&CK Group ID.
    :param columns: Columns to show. Options: ID, Group, Associated Groups.
    :return: None
    """
    sector_table = PrettyTable()
    sector_table.field_names = ["ID", "MITRE Groups", "Associated Groups"]
    for group_ in groups_from_mitre:
        sector_table.add_row(
            [
                f"{Fore.WHITE}{group_['mitre_id']}{Fore.LIGHTBLUE_EX}",
                f"{Fore.WHITE}{group_['name']}{Fore.LIGHTBLUE_EX}",
                f"{Fore.WHITE}{group_['relations']}{Fore.LIGHTBLUE_EX}"
            ]
        )
    if columns is None:
        print(f"{Fore.LIGHTBLUE_EX}{sector_table.get_string(fields=['ID', 'MITRE Groups'])}")
    else:
        print(f"{Fore.LIGHTBLUE_EX}{sector_table.get_string(fields=columns)}")


def print_mitre_softwares_table(tools: list) -> None:
    """
    Shows in the screen a table with softwares used by groups.
    :param tools: Softwares collected of group page from MITRE ATT&CK.
    :return: None
    """
    software_table = PrettyTable()
    software_table.field_names = ["Softwares Used"]
    for tool in tools:
        software_table.add_row([f"{Fore.WHITE}{tool}{Fore.LIGHTBLUE_EX}"])
    print(f"{Fore.LIGHTBLUE_EX}{software_table.get_string(fields=['Softwares Used'])}")


def perform_mitre_visibility(sector=None, group=None, ttp=None) -> dict:
    """
    Performs the MITRE functions execution.
    :param sector: Sector name.
    :param group: Group name.
    :param ttp: A bool value to 'ttp' flag.
    :return: A dict with results.
    """
    if (ttp and sector) is not None:
        mitre_output = dict()
        for group in mitre_groups_parser(sector=sector):
            try:
                print(f"\n{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Getting {Fore.BLUE}{group['name']}{Fore.WHITE} TTPs")
                group_tools = get_softwares_used_from_mitre(group_id=group["mitre_id"])
                group["navigator_url"] = get_mitre_navigator_url(group_id=group["mitre_id"])["matrix"]
                if group_tools:
                    group["softwares"] = group_tools
                else:
                    group_tools = ["None"]
                mitre_output[group["name"]] = group
                # printing results
                print(f"\n{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Description:\n\t[{Fore.BLUE}+{Fore.WHITE}] {group['description']}")
                print(f"\n{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] ATT&CK Navigator:\n\t[{Fore.BLUE}+{Fore.WHITE}] {Fore.BLUE}{group['navigator_url']}{Fore.RESET}\n")
                print_mitre_groups_table(groups_from_mitre=[group], columns=["Associated Groups"])
                print_mitre_softwares_table(tools=group_tools)
            except Exception:
                print(f"{Fore.WHITE}[{Fore.MAGENTA}!{Fore.WHITE}] Error on MITRE ATT&CK sector and ttp operations: {repr(format_exc())}")
                continue
        return {"mitre_groups": mitre_output}
    elif sector is not None:
        try:
            mitre_groups = mitre_groups_parser(sector=sector)
            print(f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Found {Fore.LIGHTBLUE_EX}{len(mitre_groups)}{Fore.WHITE} groups on MITRE ATT&CK")
            if mitre_groups:
                print_mitre_groups_table(groups_from_mitre=mitre_groups)
            return {"mitre_groups": mitre_groups}
        except Exception:
            print(f"{Fore.WHITE}[{Fore.MAGENTA}!{Fore.WHITE}] Error on MITRE ATT&CK sector operations: {repr(format_exc())}")
            return {}
    elif group:
        try:
            group_info = check_group_in_groups(groups=mitre_groups_parser(), group=group)
            if not group_info:
                print(f"{Fore.WHITE}[{Fore.MAGENTA}!{Fore.WHITE}] The {Fore.MAGENTA}{group}{Fore.WHITE} group was not found on MITRE ATT&CK")
                return {}
            else:
                group_tools = get_softwares_used_from_mitre(group_id=group_info["mitre_id"])
                group_info["softwares"] = group_tools
                group_info["navigator_url"] = get_mitre_navigator_url(group_id=group_info["mitre_id"])["matrix"]
                # printing MITRE ATT&CK results
                print(f"\n{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Description:\n\t[{Fore.BLUE}+{Fore.WHITE}] {group_info['description']}")
                print(f"\n{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] ATT&CK Navigator:\n\t[{Fore.BLUE}+{Fore.WHITE}] {Fore.BLUE}{group_info['navigator_url']}{Fore.RESET}\n")
                print_mitre_groups_table(groups_from_mitre=[group_info], columns=["Associated Groups"])
                print_mitre_softwares_table(tools=group_tools)
                return group_info
        except Exception:
            print(f"{Fore.WHITE}[{Fore.MAGENTA}!{Fore.WHITE}] Error on MITRE ATT&CK group operations: {repr(format_exc())}")
            return {}
