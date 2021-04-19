import sys

recovered = {15:0, 16:0, 17:0}
not_recovered = 0

with open(sys.argv[1], 'r') as my_file:
    for line in my_file:
        if(line.startswith("Recovered key")):
            recovered[int(line.split()[-1])] += 1
        elif(line.startswith("Not able to recover")):
            not_recovered += 1

total = 0
for k in recovered.keys():
    total += recovered[k]

total += not_recovered

print("Total:", total)
for k in recovered.keys():
    print("Recovered with", k, "=", recovered[k])

print("Not recovered:", not_recovered)