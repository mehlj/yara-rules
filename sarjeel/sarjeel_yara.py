#!/bin/python

import yara

def match_sarjeel():    
    rule_str = """rule sarjeel
    {
    meta:
            author = "mehlsec"
            description = "sarjeel malware obtained on malwr"
    strings:
            $string1 = "bogus %p"
            $string2 = "n:c:t:b:T:p:u:v:rkVhwix:y:z:C:H:P:A:g:X:de:Sq"
    condition:
            2 of them
    }
    """

    rule = yara.compile(source=rule_str)
    matches = rule.match('/home/jmehl/samples/sarjeel.exe')

    return matches

if __name__ == "__main__":
    print(match_sarjeel())
