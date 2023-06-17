from tqdm import tqdm
from requests import get
from colorama import Fore
from bs4 import BeautifulSoup
from datetime import datetime
from traceback import format_exc
from prettytable import PrettyTable


def get_elements_from_recent_activities() -> BeautifulSoup:
    """
    Request to get the html elements from Ransomlook recent publications page
    :return: The Beautifulsoup object to be parser
    """
    response = get(url="https://www.ransomlook.io/recent",
                   headers={
                       "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0",
                       "Accept": "*/*",
                       "Accept-Language": "pt - BR, pt;q = 0.8, en - US;q = 0.5, en;q = 0.3",
                       "Connection": "keep-alive",
                       "Upgrade-Insecure-Requests": "1"})
    if response.status_code == 200:
        return BeautifulSoup(response.content, "html.parser")


def get_ransomware_activities() -> list:
    """
    Collects the ransomware activities
    :return: A list of dictionaries with the date and the group name
    """
    soup = get_elements_from_recent_activities()
    raw_table, activities = soup.find_all("tr")[1:], list()
    for element in tqdm(iterable=raw_table,
                        desc=f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Collecting Ransomware Activities{Fore.BLUE}",
                        bar_format="{l_bar}{bar:10}"):
        activities.append({"date": element.get_text().strip().split(" ")[0], "name": element.find("a").get_text()})
    return activities


def get_ransomware_activities_by_group(group_name: str) -> list:
    """
    Performs group filtering in the ransomware activities.
    :param group_name: Group name.
    :return: A list of dicts with ransomware group activity data
    """
    activity_by_group = list()
    for activity in get_ransomware_activities():
        if group_name.lower() in activity["name"].lower():
            activity_by_group.append(activity)
    return activity_by_group


def count_group_hits(group_mentions: list) -> tuple:
    """
    Take the list of ransomware activities by group and count the hits.
    :param group_mentions: A list with group activities.
    :return:
    """
    group_hits_count, first_date, last_date = dict(), None, None
    for group in group_mentions:
        if (first_date and last_date) is None:
            first_date, last_date = group["date"], group["date"]
        if not group_hits_count.get(group["name"]):
            group_hits_count[group["name"]] = 1
        else:
            group_hits_count[group["name"]] += 1
            if datetime.strptime(first_date, "%Y-%m-%d").date() > datetime.strptime(group["date"], "%Y-%m-%d").date():
                first_date = group["date"]
                continue
            if datetime.strptime(last_date, "%Y-%m-%d").date() < datetime.strptime(group["date"], "%Y-%m-%d").date():
                last_date = group["date"]
                continue
    return group_hits_count, first_date, last_date


def compare_sentinel_and_ransomlook(sentinel_groups: list, ransom_activities: dict) -> dict:
    """
    Compares the groups collected from Sentinel and Ransomlook.
    :param sentinel_groups: Groups from SentinelOne.
    :param ransom_activities:Groups from Ransomlook.
    :return: A dict with common groups.
    """
    common_groups = dict()
    for group in ransom_activities:
        for sentinel_group in sentinel_groups:
            if group.replace(" ", "") in sentinel_group["name"].strip().replace("0", "o").replace(" ", "").lower():
                common_groups[group] = ransom_activities[group]
    return common_groups


def print_ransomware_activities_table(victims_count: dict) -> None:
    """
    Prints ransomware activity table.
    :param victims_count: A dict with group name and activity datetime data.
    :return: None.
    """
    activities_table = PrettyTable()
    activities_table.field_names = ["Group", "Victims"]
    for group_hits in victims_count.items():
        activities_table.add_row([f"{Fore.WHITE}{group_hits[0]}{Fore.LIGHTBLUE_EX}", f"{Fore.WHITE}{group_hits[1]}{Fore.LIGHTBLUE_EX}"])
    print(f"{Fore.LIGHTBLUE_EX}{activities_table.get_string(fields=['Group', 'Victims'])}")


def performs_ransomloook_visibility(groups_from_sentinel=None, group=None, general_activity=None) -> dict:
    """
    Invokes the Ransomlook's functions execution.
    :param groups_from_sentinel: A list with groups from SentinelOne.
    :param group: Group name.
    :param general_activity: A bool value to get the recent ransomware activities without filtering.
    :return: None.
    """
    if groups_from_sentinel:
        try:
            print(f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Looking for activities of the aforementioned ransomware groups")
            groups_victims, first_date, last_date = count_group_hits(group_mentions=get_ransomware_activities())
            common_active_groups = compare_sentinel_and_ransomlook(sentinel_groups=groups_from_sentinel, ransom_activities=groups_victims)
            if common_active_groups:
                print(f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] The results bellow occurred between {Fore.MAGENTA}{first_date}{Fore.WHITE} and {Fore.MAGENTA}{last_date}{Fore.WHITE}")
                print_ransomware_activities_table(victims_count=common_active_groups)
                return {"first_date": first_date, "last_date": last_date, "groups": common_active_groups}
            else:
                print(f"{Fore.WHITE}[{Fore.MAGENTA}!{Fore.WHITE}] No activity was found between {Fore.MAGENTA}{first_date}{Fore.WHITE} and {Fore.MAGENTA}{last_date}{Fore.WHITE}")
                return {}
        except Exception:
            print(f"{Fore.WHITE}[{Fore.MAGENTA}!{Fore.WHITE}] Error getting ransomware activities for SentinelOne groups: {repr(format_exc())}")
            return {}
    elif group:
        try:
            print(f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Looking for recent activities related to the {Fore.MAGENTA}{group}{Fore.WHITE} group")
            group_activities = get_ransomware_activities_by_group(group_name=group)
            if group_activities:
                groups_victims, first_date, last_date = count_group_hits(group_mentions=group_activities)
                print(f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] The results bellow occurred between {Fore.MAGENTA}{first_date}{Fore.WHITE} and {Fore.MAGENTA}{last_date}{Fore.WHITE}")
                print_ransomware_activities_table(victims_count=groups_victims)
                return {"first_date": first_date, "last_date": last_date, "groups": groups_victims}
            else:
                print(f"{Fore.WHITE}[{Fore.MAGENTA}!{Fore.WHITE}] No activity was found {Fore.MAGENTA}{group}{Fore.WHITE} group")
                return {}
        except Exception:
            print(f"{Fore.WHITE}[{Fore.MAGENTA}!{Fore.WHITE}] Error getting ransomware activities for {Fore.MAGENTA}{group}{Fore.WHITE}: {repr(format_exc())}")
            return {}
    elif general_activity:
        try:
            print(f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Looking for recent ransomware activities")
            groups_victims, first_date, last_date = count_group_hits(group_mentions=get_ransomware_activities())
            print(f"{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] The results bellow occurred between {Fore.MAGENTA}{first_date}{Fore.WHITE} and {Fore.MAGENTA}{last_date}{Fore.WHITE}")
            print_ransomware_activities_table(victims_count=groups_victims)
            return {"first_date": first_date, "last_date": last_date, "groups": groups_victims}
        except Exception:
            print(f"{Fore.WHITE}[{Fore.MAGENTA}!{Fore.WHITE}] Error getting general ransomware activities: {repr(format_exc())}")
            return {}
