import os
import time

try:
    while True:
        os.system("curl https://8.8.8.8")
        time.sleep(1)
except KeyboardInterrupt:
    print("sending packets done")
