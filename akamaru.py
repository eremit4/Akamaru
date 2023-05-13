from tqdm import tqdm
from requests import get
from bs4 import BeautifulSoup
from colorama import init, Fore
from traceback import format_exc as print_traceback
from argparse import ArgumentParser, SUPPRESS, HelpFormatter


class CustomHelpFormatter(HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=50, width=100)

    def format_action_invocation(self, action):
        if not action.option_strings or action.nargs == 0:
            return super().format_action_invocation(action)
        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return ', '.join(action.option_strings) + ' ' + args_string


def collect_groups_from_mitre() -> dict:
    """
    collect groups information from MITRE ATT&CK
    :return: a dict of collected information
    """
    groups = dict()
    print(f"[{Fore.LIGHTRED_EX}>{Fore.WHITE}] Collecting information from {Fore.LIGHTRED_EX}MITRE ATT&CK{Fore.WHITE}")
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
                             desc=f"\t{Fore.WHITE}[{Fore.LIGHTRED_EX}+{Fore.WHITE}] Sniffing groups{Fore.LIGHTRED_EX}",
                             mininterval=0.1,
                             bar_format="{l_bar}{bar:10}"):

                groups_raw = item.get_text().strip().split("\n")
                mitre_group_id = groups_raw[0].strip()
                mitre_group_name = groups_raw[3].strip()
                if groups_raw[6] != "":
                    mitre_associated_groups = groups_raw[6].strip()
                    mitre_group_desc = groups_raw[9].strip()
                else:
                    mitre_associated_groups = "Unknown"
                    mitre_group_desc = groups_raw[8]
                groups[mitre_group_name] = {
                    "name": mitre_group_name,
                    "mitre_id": mitre_group_id,
                    "relations": mitre_associated_groups,
                    "description": mitre_group_desc
                }
            return groups
    except Exception:
        print(print_traceback())


if __name__ == '__main__':
    arg_style = lambda prog: CustomHelpFormatter(prog)
    args = ArgumentParser(description="",  add_help=False, formatter_class=arg_style)
    group_required = args.add_argument_group(title="required arguments")
    group_required.add_argument("-s", "--sector", metavar="<sector>", type=str, help="")
    group_required.add_argument("-g", "--group", metavar="<group>", type=str, help="")

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
    collect_groups_from_mitre()

