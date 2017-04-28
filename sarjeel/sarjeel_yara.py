#!/usr/bin/env python3


import yara
import getopt
import sys


def match_sarjeel(file):    
    rule_str = """rule sarjeel
    {
    meta:
            author = "mehlsec"
            description = "sarjeel malware obtained on malwr"
    strings:
            $string1 = "bogus %p"
            $string2 = "n:c:t:b:T:p:u:v:rkVhwix:y:z:C:H:P:A:g:X:de:Sq"
    condition:
            all of them
    }
    """

    rule = yara.compile(source=rule_str)
    matches = rule.match(file)

    return matches


def get_args(argv):
    try:
        opts, args = getopt.getopt(argv, "hf:", ["file="])
    except getopt.GetoptError:
        print('./sarjeel_yara.py -f <file>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('./sarjeel_yara.py -f <file>')
            sys.exit()
        elif opt in ("-f", "--file"):
            target = arg
            return target
        else:
            print('./sarjell_yara.py -f <file')
            sys.exit()


if __name__ == "__main__":
    file = get_args(sys.argv[1:])
    print(match_sarjeel(file))

