import sys

lines = []
window_size = int(sys.argv[1]) // 2
with open(sys.argv[2], 'r') as my_file:
	for line in my_file:
		lines.append(line.strip().replace("\n",""))

# print(lines)

i=0
c = 0
start, end = -1, -1
valid_start = -1

while(i<len(lines)):
    if(lines[i] == "s g" and i+1<len(lines) and lines[i+1] == "r g"):
        c += 1
        i += 2
    elif(lines[i] == "r g"):
        c += 1
        i += 1
    else:
        c = 0
        i += 1
        # we must start with "r g" as a=p-1 or q-1 is even
        while(i<len(lines) and lines[i]=="s g"):
            i+=1
        start = i
    
    if(c==window_size):
        valid_start = start

i = valid_start
c = 0
# print("st", i)
output = ""
branch = []
while(c<window_size):
    if(lines[i] == "s g" and i+1<len(lines) and lines[i+1] == "r g"):
        c += 1
        i += 2
        output += "s,g,r,g,"
        branch.append(1)
    elif(lines[i] == "r g"):
        c += 1
        i += 1
        output += "r,g,"
        branch.append(3) # maybe 2 or 4 too after swapping
    else:
        # output += "########SOMETHING IS WRONG#######"
        exit("ERROR: SOMETHING IS WRONG")

# f = open("trace2.txt", "w")
# f.write(output)
# f.close()

f = open("public_key.txt", "r")
n = f.readline().split()[1]
n = int(n, 16)
# print(n)
e = f.readline().split()[1]
e = int(e, 16)
# print(e)

for start in [15,16,17]:
    for a in range(e):
        # if(a%1000==0):
        #     print(start, ":", a)
        
        b = e
        for i in reversed(range(0,window_size-start)):
            if(branch[i] == 1):
                a = 2*a + b
            else:
                a *= 2
        p = a+1
        if(n%p == 0):
            q = n//p
            print("Recovered key with start:", start)
            # print("Found key with start:", start, "\np =", hex(p).upper(), "\nq =", hex(q).upper())
            exit()

print("Not able to recover key :(")