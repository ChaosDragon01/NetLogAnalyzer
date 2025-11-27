import threading
import time
 
class ThreadingProgram:
    def __init__(self):
        pass
 
    def functionOne(self):
        for i in range(7):
            print('Thread execution in progress')
        time.sleep(2)
  
    def functionTwo(self):
        ('function Two Started')
        time.sleep(10)
        print('function Two Ended')
  
  
    def threaded_exec(self):
        thread1 = threading.Thread(target = self.functionOne)
        thread2 = threading.Thread(target = self.functionTwo)
        thread2.start()
        thread1.start()
 
try: 
    thp=ThreadingProgram()
    thp.threaded_exec()
except:
    print('Threading Logic Error')