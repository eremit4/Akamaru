from tqdm import tqdm
from time import sleep
from requests import get
from bs4 import BeautifulSoup
from colorama import init, Fore
from traceback import format_exc as print_traceback
from argparse import ArgumentParser, HelpFormatter


class CustomHelpFormatter(HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=50, width=100)

    def format_action_invocation(self, action) -> str:
        if not action.option_strings or action.nargs == 0:
            return super().format_action_invocation(action)
        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return ", ".join(action.option_strings) + " " + args_string


def collect_groups_from_mitre(keyword: str) -> list:
    """
    collect groups information from MITRE ATT&CK
    :return: a dict of collected information
    """
    groups = list()
    try:
        response = get(url="https://attack.mitre.org/groups/",
                       headers={
                           "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0",
                           "Accept": "*/*",
                           "Accept-Language": "pt - BR, pt;q = 0.8, en - US;q = 0.5, en;q = 0.3",
                           "Connection": "keep-alive",
                           "Upgrade-Insecure-Requests": "1"})
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, "html.parser")
            for item in tqdm(iterable=soup.find_all("tr")[1:],
                             desc=f"{Fore.WHITE}[{Fore.LIGHTRED_EX}>{Fore.WHITE}] Collecting relevant groups from MITRE ATT&CK{Fore.LIGHTRED_EX}",
                             bar_format="{l_bar}{bar:10}"):
                groups_raw = item.get_text().strip().split("\n")
                mitre_group_id, mitre_group_name = groups_raw[0].strip(), groups_raw[3].strip()
                if groups_raw[6] != "":
                    mitre_associated_groups, mitre_group_desc = groups_raw[6].strip(), groups_raw[9].strip()
                else:
                    mitre_associated_groups, mitre_group_desc = "Unknown", groups_raw[8]
                group = {
                    "name": mitre_group_name,
                    "mitre_id": mitre_group_id,
                    "relations": mitre_associated_groups,
                    "description": mitre_group_desc
                }
                for keyword_ in sector_identify_similarities(sector_name=keyword):
                    if keyword_ in mitre_group_desc and group not in groups:
                        groups.append(group)
                sleep(0.002)
            return groups
    except Exception:
        print(print_traceback())


def sector_identify_similarities(sector_name: str) -> list:
    """

    :param sector_name:
    :return:
    """
    if sector_name == "financial":
        return ["economic", "bank", "financial"]
    if sector_name == "healthcare":
        return ["health", "healthcare", "hospital", "pharmaceutical", "medical", "disease"]
    if sector_name == "ics":
        return ["manufacturing", "mining", "chemistry", "energy", "critical infrastructure", "nuclear", "petroleum", "semicondutor", "airline"]
    if sector_name == "defense":
        pass
    if sector_name == "government":
        pass
    if sector_name == "technology":
        pass


def main(args_: ArgumentParser) -> None:
    """

    :argument args_:
    :return:
    """
    parser, collect_groups = args_.parse_args(), None
    if parser.sector:
        collected_groups = collect_groups_from_mitre(keyword=parser.sector)
        print(f"{Fore.WHITE}[{Fore.LIGHTRED_EX}>{Fore.WHITE}] Relevant groups found: {Fore.LIGHTRED_EX}{len(collected_groups)}{Fore.WHITE}")
        for group in range(len(collected_groups)):
            print(f"\t[{Fore.LIGHTRED_EX}{group+1}{Fore.WHITE}] {Fore.LIGHTRED_EX}{collected_groups[group]['name']}{Fore.WHITE}")

    elif parser.groups:
        pass
    else:
        args_.print_help()


if __name__ == '__main__':
    arg_style = lambda prog: CustomHelpFormatter(prog)
    args = ArgumentParser(description="",  add_help=False, formatter_class=arg_style)
    # well known threat groups
    group_required = args.add_argument_group(title="Well Known Threat Groups")
    group_required.add_argument("-s", "--sector", metavar="<sector>", type=str, help="Receives the sector name of your interesting. Sectors accepted: financial, healthcare, ics, defense, government, technology, education.")
    group_required.add_argument("-g", "--group", metavar="<group>", type=str, help="Receives the name of the threat group and return the known information about them.")
    # ransomware activities
    group_required = args.add_argument_group(title="Ransomware Activities")
    group_required.add_argument("-r", "--ransomware-activities", action="store_true", help="Returns the most active ransomware groups for the month.")
    # outputs
    group_required = args.add_argument_group(title="Outputs")
    group_required.add_argument("-oj", "--output-json", action="store_true", help="Returns all results in a json file.")
    group_required.add_argument("-oc", "--output-csv", action="store_true", help="Returns all the results in a csv file.")
    # help
    group_required = args.add_argument_group(title="Help")
    group_required.add_argument("-h", "--help", action="help", help="Show this help screen.")

    # perform coloroma multiplatform
    init(strip=False)
    print(r"""{}
                          __                                                        
                         |  \                                                       
                  ______ | ▓▓   __  ______  ______ ____   ______   ______  __    __ 
                 |      \| ▓▓  /  \|      \|      \    \ |      \ /      \|  \  |  \
                  \▓▓▓▓▓▓\ ▓▓_/  ▓▓ \▓▓▓▓▓▓\ ▓▓▓▓▓▓\▓▓▓▓\ \▓▓▓▓▓▓\  ▓▓▓▓▓▓\ ▓▓  | ▓▓
                 /      ▓▓ ▓▓   ▓▓ /      ▓▓ ▓▓ | ▓▓ | ▓▓/      ▓▓ ▓▓   \▓▓ ▓▓  | ▓▓
                |  ▓▓▓▓▓▓▓ ▓▓▓▓▓▓\|  ▓▓▓▓▓▓▓ ▓▓ | ▓▓ | ▓▓  ▓▓▓▓▓▓▓ ▓▓     | ▓▓__/ ▓▓
                 \▓▓    ▓▓ ▓▓  \▓▓\\▓▓    ▓▓ ▓▓ | ▓▓ | ▓▓\▓▓    ▓▓ ▓▓      \▓▓    ▓▓
                  \▓▓▓▓▓▓▓\▓▓   \▓▓ \▓▓▓▓▓▓▓\▓▓  \▓▓  \▓▓ \▓▓▓▓▓▓▓\▓▓       \▓▓▓▓▓▓ 
                                                                                       
                                          {}[{}>{}] Sniffing information about threat groups
                                          [{}>{}] eremit4@protonmail.com                                          
    """.format(Fore.LIGHTRED_EX, Fore.WHITE, Fore.LIGHTRED_EX, Fore.WHITE, Fore.LIGHTRED_EX, Fore.WHITE))
    try:
        main(args_=args)
    except Exception:
        print(print_traceback())
