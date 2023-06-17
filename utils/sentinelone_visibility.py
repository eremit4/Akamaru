from tqdm import tqdm
from requests import get
from colorama import Fore
from bs4 import BeautifulSoup
from traceback import format_exc
from prettytable import PrettyTable
from utils.util import get_sector_keywords, check_group_in_groups
from utils.ransomlook_visibility import performs_ransomloook_visibility
from utils.google_search_visibiity import search_for_group_analysis_on_google


def get_elements_from_anthology_page() -> BeautifulSoup:
    """
    Get html elements from SentinelOne Anthology page.
    :return: The Beautifulsoup object to be parser.
    """
    response = get(url="https://www.sentinelone.com/anthology",
                   headers={
                       "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0",
                       "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                       "Accept-Language": "pt - BR, pt;q = 0.8, en - US;q = 0.5, en;q = 0.3",
                       "Connection": "keep-alive",
                       "Upgrade-Insecure-Requests": "1"})
    if response.status_code == 200:
        return BeautifulSoup(response.content, "html.parser")


def get_elements_from_anthology_group_page(anthology_group_url: str) -> BeautifulSoup:
    """
    Gets the html elements from SentinelOne Ransomware Anthology group page.
    :param anthology_group_url: Group url.
    :return: The Beautifulsoup object to be parser.
    """
    response = get(url=anthology_group_url,
                   headers={
                       "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0",
                       "Accept": "*/*",
                       "Accept-Language": "pt - BR, pt;q = 0.8, en - US;q = 0.5, en;q = 0.3",
                       "Connection": "keep-alive",
                       "Upgrade-Insecure-Requests": "1"})
    if response.status_code == 200:
        return BeautifulSoup(response.content, "html.parser")


def get_sentinel_groups_information(sector=None) -> list:
    """
    Acquire information like group name, url, and description of html elements collected from SentinelOne.
    :param sector:
    :return: A list of dict with information about groups.
    """
    soup, groups = get_elements_from_anthology_page(), list()
    raw_table = soup.find_all("div", {"class": "anthology-entry"})
    for element in tqdm(iterable=raw_table,
                        desc=f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Collecting relevant groups from SentinelOne{Fore.BLUE}",
                        bar_format="{l_bar}{bar:10}"):
        name = element.find("h3").get_text(),
        url = element.find("a").attrs["href"],
        desc = get_sentinel_group_description(group_url=element.find("a").attrs["href"])
        group = {"name": name[0], "url": url[0], "description": desc}
        try:
            if sector is not None:
                for keyword_ in get_sector_keywords(sector_name=sector):
                    if keyword_ in desc and group not in groups:
                        groups.append(group)
            else:
                groups.append(group)
        except TypeError:
            pass
    return groups


def get_sentinel_group_description(group_url: str) -> str:
    """
    Get the group description.
    :param group_url: Group url.
    :return: The group description.
    """
    try:
        blog_elements = get_elements_from_anthology_group_page(anthology_group_url=group_url).find_all("div", {"class": "content-wrapper"})[0].text.splitlines()
        for element in blog_elements:
            if "Target?" in element:
                description, position = "", blog_elements.index(element) + 1
                while "?" not in blog_elements[position]:
                    if len(blog_elements[position]) != 0:
                        description += f" {blog_elements[position]}"
                        position += 1
                    else:
                        position += 1
                return description.strip()
            if "Target?" in element and len(blog_elements[blog_elements.index(element) + 1]) > 0:
                return blog_elements[blog_elements.index(element) + 1].strip()
    except AttributeError:
        pass


def try_to_find_a_hide_group_from_sentinelone(group_name: str):
    """
    Try to access a hide article about a specific group.
    :param group_name: Group name.
    :return: A dict with group information.
    """
    print(f"{Fore.WHITE}[{Fore.MAGENTA}!{Fore.WHITE}] The {Fore.MAGENTA}{group_name}{Fore.WHITE} group is not listed on the Ransomware Anthology main page")
    print(f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Trying to find {Fore.MAGENTA}{group_name}{Fore.WHITE} group manually")
    group_url = f"https://www.sentinelone.com/anthology/{group_name}"
    response = get(url=group_url,
                   headers={
                       "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0",
                       "Accept": "*/*",
                       "Accept-Language": "pt - BR, pt;q = 0.8, en - US;q = 0.5, en;q = 0.3",
                       "Connection": "keep-alive",
                       "Upgrade-Insecure-Requests": "1"})
    if response.status_code == 200:
        return {"name": group_name, "url": group_url, "description": get_sentinel_group_description(group_url=group_url)}
    else:
        return {}


def print_sentinel_groups_table(groups_from_sentinel: list) -> None:
    """
    Shows in the screen a table with groups collected from MITRE ATT&CK.
    :param groups_from_sentinel: MITRE ATT&CK Group ID.
    :return: None
    """
    sector_table = PrettyTable()
    sector_table.field_names = ["SentinelOne Groups"]
    for group_ in groups_from_sentinel:
        sector_table.add_row([f"{Fore.WHITE}{group_['name'].strip()}{Fore.LIGHTBLUE_EX}"])
    print(f"{Fore.LIGHTBLUE_EX}{sector_table.get_string(fields=['SentinelOne Groups'])}")


def performs_sentinel_visibility(sector=None, group=None) -> dict:
    """
    Performs the MITRE functions execution.
    :param sector: Sector name.
    :param group: Group name.
    :return: None
    """
    print(f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Preparing to get ransomware groups from SentinelOne. Sometimes the page may be slow")
    if sector:
        try:
            sentinel_groups = get_sentinel_groups_information(sector=sector)
            print(f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Found {Fore.LIGHTBLUE_EX}{len(sentinel_groups)} {Fore.WHITE}ransomware groups on SentinelOne")
            if sentinel_groups:
                print_sentinel_groups_table(groups_from_sentinel=sentinel_groups)
                activities = performs_ransomloook_visibility(groups_from_sentinel=sentinel_groups)
                for actor in activities.get("groups"):
                    search_for_group_analysis_on_google(group_name=actor)
                return {"groups": sentinel_groups, "activities": activities.get("groups")}
            else:
                return {}
        except Exception:
            print(f"{Fore.WHITE}[{Fore.MAGENTA}!{Fore.WHITE}] Error on SentinelOne sector operation: {repr(format_exc())}")
            return {}
    elif group:
        try:
            group_info = check_group_in_groups(groups=get_sentinel_groups_information(), group=group)
            if not group_info:
                # trying to find the group manually (some articles it's not listed on the main page)
                group_info = try_to_find_a_hide_group_from_sentinelone(group_name=group)
                if not group_info:
                    print(f"{Fore.WHITE}[{Fore.MAGENTA}!{Fore.WHITE}] The {Fore.MAGENTA}{group}{Fore.WHITE} group was not found on SentinelOne")
                    return {}
                else:
                    print(f"\n{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Description:\n\t[{Fore.BLUE}+{Fore.WHITE}] {group_info['description']}")
                    group_info["activities"] = performs_ransomloook_visibility(group=group)
                    for actor in group_info["activities"]["groups"]:
                        search_for_group_analysis_on_google(group_name=actor)
                    return group_info
            else:
                print(f"\n{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Description:\n\t[{Fore.BLUE}+{Fore.WHITE}] {group_info['description']}")
                group_info["activities"] = performs_ransomloook_visibility(group=group)
                for actor in group_info["activities"]["groups"]:
                    search_for_group_analysis_on_google(group_name=actor)
                return group_info
        except Exception:
            print(f"{Fore.WHITE}[{Fore.MAGENTA}!{Fore.WHITE}] Error on SentinelOne groups operation: {repr(format_exc())}")
            return {}
