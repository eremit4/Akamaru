# Akamaru
>In the day-to-day life of a CTI or Threat Hunting team, one of the main tasks is trying to answer the questions: who are my enemies? what are the threat groups that affect my industry?
Doing this mapping can take an analyst many hours, even weeks. Considering the Threat Intelligence Lifecycle, Akamaru aims to automate the initial phase of Collect by collecting the threat groups and some relevant TTPs from [MITRE](https://attack.mitre.org/groups/), [Ransomware Anthology](https://www.sentinelone.com/anthology/) (SentinelOne), and [Ransomlook](https://www.ransomlook.io/recent), just informing the name of the sector of interest (e.g. financial, education, defense) or the name of the group (e.g. Akira, Lockbit) in order to get more information about it.

![](./utils/akamaru_logo.png)

## 🐾 Setup

Cloning the project:
```bash
git clone https://github.com/eremit4/Akamaru.git
```
Optional - Creating a virtualenv before installing the dependencies
> Note: The use of virtual environments is optional, but recommended. In this way, we avoid possible conflicts in different versions of the project's dependencies.
> Learn how to install and use virtualenv according to your OS [here](https://virtualenv.pypa.io/en/latest/)

Installing the dependencies:
```bash
pip install -r requirements.txt
```

## 🐶 Running

Discovering the project capabilities:
```bash
python akamaru.py --help
```

Discovering which sectors are supported:
```bash
python akamaru.py -ss
```

Finding only the groups relevant to a given sector:
```bash
python akamaru.py --sector <name>
```

Finding the relevant groups for a given sector, their TTPs, and returning everything in a CSV file:
```bash
python akamaru.py --sector <name> --ttp --output
```

Looking for information about a particular group:
```bash
python akamaru.py --group <name>
```

Looking for ransomware activities:
```bash
python akamaru.py --ransomware-activities
```

## 🐕 Demo
[![asciicast](https://asciinema.org/a/591986.svg)](https://asciinema.org/a/591986)

## 📝 License
This project is under the [MIT License](LICENSE).
