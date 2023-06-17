# Akamaru
> This project aims to automate part of the process of mapping groups of threats relevant to a provided sector. After receiving the sector name (e.g. financial, education, etc.), Akamaru parses the description of groups on [MITRE ATT&CK](https://attack.mitre.org/groups/) and [Ransomware Anthology](https://www.sentinelone.com/anthology/) (SentinelOne) to filter and return information about groups that affect the sector in question.
> After collecting the groups, compare the results with recent activities of ransomware groups (approximately 7 days) and look for analysis of groups that are in both Ransomware Anthology results and recent [Ransomlook](https://www.ransomlook.io/recent) activities.

![akamaru](https://i.gifer.com/8HpQ.gif)

## 🐾 Setup

Cloning the project:
```bash
git clone https://github.com/eremit4/Akamaru.git
```
Optional - Create a virtualenv before install the dependencies
> Note: The use of virtual environments is optional, but recommended. In this way, we avoid possible conflicts in different versions of project's dependencies.
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

Finding only the groups relevant to a given sector:
```bash
python akamaru.py --sector <name>
```

Finding the relevant groups for a given sector, their TTPs, and returns everything in a CSV file:
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
[![asciicast](https://asciinema.org/a/591938.svg)](https://asciinema.org/a/591938)

## 📝 License
This project is under the [MIT License](LICENSE).
