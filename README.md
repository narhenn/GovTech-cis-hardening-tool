# cis-hardening-checker

Automates CIS Benchmark compliance checks on RHEL servers over SSH. 
reads rules from a yaml config, runs the check commands on the target server, and tells you what passed/failed.

## setup

```
pip install -r requirements.txt
```

## usage

```bash
# single server
python main.py --hosts 192.168.1.10 --user root --key ~/.ssh/id_rsa

# multiple servers
python main.py --hosts 192.168.1.10,192.168.1.11 --user admin --key ~/.ssh/id_rsa

# only check ssh rules
python main.py --hosts 192.168.1.10 --user root --key ~/.ssh/id_rsa --category ssh

# save as json or html
python main.py --hosts 192.168.1.10 --user root --format json --output report.json
python main.py --hosts 192.168.1.10 --user root --format html --output report.html
```

## adding rules

edit `config/cis_rules.yaml`. each rule has a shell command to run and the expected output. match types: `exact`, `contains`, `absent`, `regex`.

## tests

```
python -m pytest tests/ -v
```
