#!/usr/bin/python

import os
import time
import main
import Queue
import threading
import multiprocessing

Lobotomy = main.Lobotomy()


class myThread (threading.Thread):
    def __init__(self, threadID, name, q):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.q = q

    def run(self):
        print "{}: Starting".format(self.name)
        process_data(self.name, self.q)
        time.sleep(0.2)
        print "{}: Exiting".format(self.name)


def process_data(threadName, q):
    while not exitFlag:
        queueLock.acquire()
        if not workQueue.empty():
            data = q.get()
            queueLock.release()
            
            print "{} processing {}".format(threadName, data)

            Lobotomy.write_to_main_log('QUEUE PROCESSOR', "Starting running from queue: {}".format(data))
            os.system(data)
            Lobotomy.write_to_main_log('QUEUE PROCESSOR', "Finished running from queue: {}".format(data))
            
        else:
            queueLock.release()
        time.sleep(3)

if __name__ == "__main__":
    cpucount = multiprocessing.cpu_count()
    while True:

        threadList = []
        for threadcount in range(cpucount):
            threadList.append('Lobotomy Thread-{}'.format(threadcount))
        queueLock = threading.Lock()
        workQueue = Queue.Queue(cpucount)
        threads = []
        threadID = 1    

        exitFlag = 0

        # Create new threads
        for tName in threadList:
            time.sleep(0.2)
            thread = myThread(threadID, tName, workQueue)
            thread.start()
            threads.append(thread)
            threadID += 1

        # Fill the queue
        queueLock.acquire()
        for word in threadList:
            try:
                data = Lobotomy.read_from_queue()
                #id = data['id']
                command = data['command']
                priority = data['priority']
                workQueue.put(command)
            except:
                print "{}: Nothing to do".format(word)
                time.sleep(2)
        queueLock.release()

        # Wait for queue to empty
        while not workQueue.empty():
            pass

        # Notify threads it's time to exit
        exitFlag = 1

        # Wait for all threads to complete
        for t in threads:
            time.sleep(0.1)
            t.join()
            time.sleep(0.1)
        print "Exiting Main Thread"
        time.sleep(1)
