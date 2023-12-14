from requests import get
from colorama import Fore
from bs4 import BeautifulSoup


def search_for_group_analysis_on_google(group_name: str, ) -> None:
    """
    Search the target on Google to look for mentions of it.
    :param group_name: The name of the group to find analysis on Google Search.
    :return: None
    """
    def google_search_request(dork: str) -> bytes:
        """
        Performs the request on Google Search.
        :param dork: Google Dork.
        :return: Response in HTML content bytes.
        """
        return get(url=f"https://www.google.com/search?q={dork}",
                   headers={
                       "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0",
                       "Accept": "*/*",
                       "Accept-Language": "pt - BR, pt;q = 0.8, en - US;q = 0.5, en;q = 0.3",
                       "Connection": "keep-alive",
                       "Upgrade-Insecure-Requests": "1"}).content

    a_tags, count = BeautifulSoup(google_search_request(dork=f"intext:{group_name} intext:ransomware intext:analysis"), 'html.parser').find_all("a"), 0
    print(f"\n{Fore.WHITE}[{Fore.BLUE}>{Fore.WHITE}] Looking for analysis about {Fore.MAGENTA}{group_name}{Fore.WHITE} group")
    for link in a_tags:
        if link.attrs.get("href") and not check_blacklist(link_=link.attrs.get("href")) and choose_priority_sources(source_url=link.attrs.get('href')) and count < 6:
            print(f"\t{Fore.WHITE}[{Fore.MAGENTA}{count + 1}{Fore.WHITE}] {link.attrs.get('href')}")
            count += 1


def check_blacklist(link_: str) -> bool:
    """
    checks if the link collected is relevant or not
    :param link_: link collected
    :return: True if this link is blacklisted or False if not
    """
    for term in ["google.com", "/search?q=", "youtube.com", "#", "oem.avira.com"]:
        if term in link_:
            return True
    return False


def choose_priority_sources(source_url: str) -> bool:
    """
    Choose some sources to suggest to the user.
    :param source_url: Source URL.
    :return: True if there is any keyword bellow in URL received, otherwise it returns False.
    """
    for source in ["sentinelone", "trellix", "trendmicro", "mandiant", "sophos", "cisa.gov", "kaspersky", "paloalto", "crowstrike", "malwarebytes", "cyble", "socradar", "cybereason"]:
        if source in source_url:
            return True
    return False
