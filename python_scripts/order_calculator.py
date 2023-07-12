
GROUP_SIZE = 47
BASE = 6


for n in range(1,GROUP_SIZE):
    res = (BASE**n)%GROUP_SIZE
    print('Iteration n: ' + str(n) + ' Result: ' + str(res))
    if(res == 1):
        break