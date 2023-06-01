from colorama import init, Fore
from argparse import ArgumentParser, HelpFormatter
from traceback import format_exc as print_traceback
from utils.mitre_visibility import mitre_groups_parser, get_softwares_used_from_mitre, print_mitre_groups_table, \
    get_mitre_navigator_url, print_mitre_softwares_table


class CustomHelpFormatter(HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=50, width=100)

    def format_action_invocation(self, action) -> str:
        if not action.option_strings or action.nargs == 0:
            return super().format_action_invocation(action)
        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return ", ".join(action.option_strings) + " " + args_string


def main(args_: ArgumentParser) -> None:
    """
    Manages all the Akamaru's process
    :argument args_: arguments from the command line
    :return: None
    """
    parser, mitre_groups, mitre_group_info, sentinel_groups, sentinel_group_info = args_.parse_args(), None, None, None, None
    if parser.sector:
        mitre_groups = mitre_groups_parser(sector=parser.sector)
        print(f"{Fore.WHITE}[{Fore.RED}>{Fore.WHITE}] Found {Fore.RED}{len(mitre_groups)} {Fore.WHITE}groups on MITRE ATT&CK")
        print_mitre_groups_table(groups_from_mitre=mitre_groups)

    elif parser.group:
        mitre_group_info = None
        for group_ in mitre_groups_parser():
            if str(parser.group).lower() in group_["name"].lower():
                group_info = group_
                break
        # checking group on MITRE ATA&CK
        if mitre_group_info is None:
            print(f"{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] Group {Fore.RED}{parser.group}{Fore.WHITE} not found")
            exit(0)
        else:
            group_tools = get_softwares_used_from_mitre(group_id=mitre_group_info["mitre_id"])
            # printing results
            print(f"\n{Fore.WHITE}[{Fore.RED}>{Fore.WHITE}] Description:\n\t[{Fore.RED}+{Fore.WHITE}] {mitre_group_info['description']}")
            print(f"\n{Fore.WHITE}[{Fore.RED}>{Fore.WHITE}] ATT&CK Navigator:\n\t[{Fore.RED}+{Fore.WHITE}] {Fore.RED}{get_mitre_navigator_url(group_id=mitre_group_info['mitre_id'])['matrix']}{Fore.RESET}\n")
            print_mitre_groups_table(groups_from_mitre=[mitre_group_info], columns=["Associated Groups"])
            print_mitre_softwares_table(tools=group_tools)

    if parser.ttps and mitre_groups is not None:
        for group in mitre_groups:
            print(f"\n{Fore.WHITE}[{Fore.RED}>{Fore.WHITE}] Getting {Fore.RED}{group['name']}{Fore.WHITE} TTPs")
            group_tools = get_softwares_used_from_mitre(group_id=group["mitre_id"])
            # printing results
            print(f"\n{Fore.WHITE}[{Fore.RED}>{Fore.WHITE}] Description:\n\t[{Fore.RED}+{Fore.WHITE}] {group['description']}")
            print(f"\n{Fore.WHITE}[{Fore.RED}>{Fore.WHITE}] ATT&CK Navigator:\n\t[{Fore.RED}+{Fore.WHITE}] {Fore.RED}{get_mitre_navigator_url(group_id=group['mitre_id'])['matrix']}{Fore.RESET}\n")
            print_mitre_groups_table(groups_from_mitre=[group], columns=["Associated Groups"])
            print_mitre_softwares_table(tools=group_tools)

    if not parser.sector \
            and not parser.group \
            and not parser.ttps \
            and not parser.ransomware_activities \
            and not parser.output_csv:
        args_.print_help()


if __name__ == '__main__':
    arg_style = lambda prog: CustomHelpFormatter(prog)
    args = ArgumentParser(description="",  add_help=False, formatter_class=arg_style)
    # well known threat groups
    group_required = args.add_argument_group(title="Well Known Threat Groups")
    group_required.add_argument("-s", "--sector", metavar="<sector>", type=str, required=False, help="Receives the sector name of your interesting. Sectors accepted: financial, healthcare, ics, defense, government, technology, education.")
    group_required.add_argument("-g", "--group", metavar="<group>", type=str, required=False, help="Receives the name of the threat group and return the known information about them.")
    group_required.add_argument("-t", "--ttps", action="store_true", help="Returns TTPs associated with groups. Due to the excessive information, isn't recommended to use this option with the flag <section> without the flag <output>.")
    # ransomware activities
    group_required = args.add_argument_group(title="Ransomware Activities")
    group_required.add_argument("-r", "--ransomware-activities", action="store_true", help="Returns the most active ransomware groups for the month.")
    # outputs
    group_required = args.add_argument_group(title="Outputs")
    group_required.add_argument("-oc", "--output-csv", action="store_true", help="Returns all the results in a csv file.")
    # help
    group_required = args.add_argument_group(title="Help")
    group_required.add_argument("-h", "--help", action="help", help="Show this help screen.")

    # perform coloroma multiplatform
    init(strip=False)
    print(r"""{}
                                 _      _                                               
                                / \    | | __   __ _   _ __ ___     __ _   _ __   _   _ 
                               / _ \   | |/ /  / _` | | '_ ` _ \   / _` | | '__| | | | |
                              / ___ \  |   <  | (_| | | | | | | | | (_| | | |    | |_| |
                             /_/   \_\ |_|\_\  \__,_| |_| |_| |_|  \__,_| |_|     \__,_|                                                                
                             
                                          {}[{}>{}] Acquiring information about threat groups
                                          [{}>{}] eremit4@protonmail.com                                          
    """.format(Fore.MAGENTA, Fore.WHITE, Fore.BLUE, Fore.WHITE, Fore.BLUE, Fore.WHITE))
    try:
        main(args_=args)
        # pass
    except Exception:
        print(print_traceback())
