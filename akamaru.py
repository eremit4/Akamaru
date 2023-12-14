from colorama import init, Fore
from argparse import ArgumentParser, HelpFormatter
from traceback import format_exc as print_traceback
from utils.mitre_visibility import perform_mitre_visibility
from utils.util import create_csv_report, print_supported_sectors
from utils.sentinelone_visibility import performs_sentinel_visibility
from utils.ransomlook_visibility import performs_ransomlook_visibility


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
    Manages all Akamaru's process
    :argument args_: arguments from the command line
    :return: None
    """
    parser, mitre_results, sentinel_results, ransomlook_results = args_.parse_args(), {}, {}, {}
    if parser.ttp and parser.sector:
        mitre_results = perform_mitre_visibility(sector=parser.sector, ttp=True)
        sentinel_results = performs_sentinel_visibility(sector=parser.sector)

    elif parser.sector:
        mitre_results = perform_mitre_visibility(sector=parser.sector)
        sentinel_results = performs_sentinel_visibility(sector=parser.sector)

    elif parser.group:
        mitre_results = perform_mitre_visibility(group=parser.group)
        sentinel_results = performs_sentinel_visibility(group=parser.group)

    elif parser.ransomware_activities:
        performs_ransomlook_visibility(general_activity=True)

    elif parser.supported_sectors:
        print_supported_sectors()

    if parser.output:
        create_csv_report(mitre=mitre_results, sentinel=sentinel_results, ttp=parser.ttp)

    if not parser.sector \
            and not parser.group \
            and not parser.ttp \
            and not parser.ransomware_activities \
            and not parser.supported_sectors \
            and not parser.output:
        args_.print_help()


if __name__ == '__main__':
    arg_style = lambda prog: CustomHelpFormatter(prog)
    args = ArgumentParser(description="",  add_help=False, formatter_class=arg_style)
    # well known threat groups
    group_required = args.add_argument_group(title="Well Known Threat Groups")
    group_required.add_argument("-s", "--sector", metavar="<sector>", type=str, required=False, help="Receives the sector name of your interesting and returns the well-known groups related. Use the -ss option to know whats sectors are supported.")
    group_required.add_argument("-ss", "--supported-sectors", action="store_true", help="Returns the supported sectors by Akamaru.")
    group_required.add_argument("-t", "--ttp", action="store_true", help="Returns TTPs associated with groups collected from MITRE ATT&CK. It must be used with the <sector> flag. Due to information overload, using this option without the <output> flag is not recommended.")
    group_required.add_argument("-g", "--group", metavar="<group>", type=str, required=False, help="Receives the name of the threat group and returns the known information about them.")
    # ransomware activities
    group_required = args.add_argument_group(title="Ransomware Activities")
    group_required.add_argument("-r", "--ransomware-activities", action="store_true", help="Returns the most active ransomware groups over a time range.")
    # outputs
    group_required = args.add_argument_group(title="Outputs")
    group_required.add_argument("-o", "--output", action="store_true", help="Returns the <sector> or <group> results in a CSV file, separated by semicolon.")
    # help
    group_required = args.add_argument_group(title="Help")
    group_required.add_argument("-h", "--help", action="help", help="Show this help screen.")

    # perform coloroma multiplatform
    init(strip=False)
    print(r"""{}
                                          _
                                        ,/A\,
                                      .//`_`\\,
                                    ,//`____-`\\,
                                  ,//`[{}Akamaru{}]`\\,
                                ,//`=  ==  __-  _`\\,
                               //|__=  __- == _  __|\\  
                               ` |  __ .-----.  _  | `  
                                 | - _/       \-   |
                                 |__  |{} .-"-. {}| __=|
                                 |  _=|{}/)   (\{}|    |
                                 |-__ {}(/ {}- -{} \){} -__|
                                 |___ {}/`\_Y_/`\{}____|
                                      {}\)     (/
                       {}[{}>{}] Sniffing out relevant threat groups
                       [{}>{}] eremit4@protonmail.com
                                         
    """.format(Fore.LIGHTBLACK_EX, Fore.MAGENTA,
               Fore.LIGHTBLACK_EX, Fore.LIGHTWHITE_EX,
               Fore.LIGHTBLACK_EX, Fore.LIGHTWHITE_EX,
               Fore.LIGHTBLACK_EX, Fore.LIGHTWHITE_EX,
               Fore.LIGHTRED_EX, Fore.LIGHTWHITE_EX,
               Fore.LIGHTBLACK_EX, Fore.LIGHTWHITE_EX,
               Fore.LIGHTBLACK_EX, Fore.LIGHTWHITE_EX,
               Fore.WHITE, Fore.MAGENTA, Fore.WHITE,
               Fore.MAGENTA, Fore.WHITE))
    try:
        main(args_=args)
    except KeyboardInterrupt:
        print(f"\n{Fore.WHITE}[{Fore.MAGENTA}!{Fore.WHITE}] OK! I will cancel operations and await your commands.\n")
    except Exception:
        print(f"\n{Fore.WHITE}[{Fore.MAGENTA}!{Fore.WHITE}] An error forced Akamaru to stop: {repr(print_traceback())}")
