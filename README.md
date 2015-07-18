# Fuzzarella - Fuzzing with pcaps 

## Status: Unmaintained


The idea is to try to test evasion against applications that are able to read pcap

You should get a clean pcap file, write a rule to match it, from this pcap baseline, fuzz it to many mutations and run your application with the same rule and see the behaviour:

What are the intentions:

1-) Try to evade IPS/FW/IDS
2-) Try to bypass protocol validation if it exists
3-) Break the application parsing trash 
4-) ... everything while you are eating your Pizza =)

TODO:

Go beyond HTTP
