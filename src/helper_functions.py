import time
import heapq
from datetime import datetime
from datetime import timedelta
import traceback
import sys

def process_line(sample, ips, dates, requests, blocked, warning, output):
    """
    This method manages helper methods for processing a single line from the file.
    The method takes in dictionaries and lists for only the fields necessary to
    calculate the features -- IP addresses, dates, requested items, blocked users,
    and users to potentially block
    """
    
    ip = sample[:sample.find(' - - ')] #isolate IP address
    date = datetime.strptime(sample[sample.find("[")+1:sample.find("]")-6], '%d/%b/%Y:%H:%M:%S')
    dates.append(date) #format and append date of request
    requestindex = 0
    endindex = 0
    offset = 5 #offset applied to parse for POST and HEAD
    request = ''
    found = False
    requestheads = ['GET','POST','HEAD']
    http = 'HTTP/1.0"'
    for i in requestheads:
        if i in sample:
            if i == 'GET':
                offset = 4 #offset fixed for GET
            requestindex = sample.find(i)
            if http in sample: #some lines end in HTTP/1.0, some don't
                endindex = sample.find(http, requestindex)
            else:
                endindex = sample.find("\"", requestindex)
            request = sample[requestindex+offset:endindex]
            found = True #when request has been indexed, break the loop
            break
    if found == False: #some lines have no HTTP methods
        requestindex = sample.find("\"")
        if http in sample:
            endindex = sample.find(http, requestindex)
        else:
            endindex = sample.find("\"", requestindex)
        request = sample[requestindex+offset:endindex]
        
    requestindex = sample.find(" ",endindex)
    endindex = sample.find(" ",requestindex + 1)
    code = sample[requestindex+1:endindex]
    size = sample[endindex+1:-1]
    
    if size == '-': #transform the '-' values at the end of the line to 0
        size = 0
    else:
        size = int(size)
    
    if ip in ips.keys(): #increment IP address frequencies
        ips[ip] += 1
    else:
        ips[ip] = 1
        
    if request in requests.keys(): #build dictionary for calculating bandwith size
        requests[request] += size
    else:
        requests[request] = size
    sample = sample[:-1] #erase linebreak \n
    blocked, warning, output = find_blocked(date, code, ip, sample, blocked, warning, output)
    #updates main method variables for sequential analysis
    return ips, requests, dates, blocked, warning, output
    
def process_dates(dates):
    """
    Function implements two forward searches to pinpoint the starting
    and ending index of web traffic for a particular time. The search
    iterates and counts through a 60 minute window for each second of
    web traffic history to find the traffic frequencies of each 60
    window. This search progresses in O(N) time. This search assumes
    that all web traffic text is in chronological order. 
    """
    
    init = dates[0] #initialize the start date
    counter = {}
    endindex = 0 
    startindex = 0
    count = 0
    difference = timedelta(0,3600) #benchmark to measure if 60 minute window has passed
    
    #iterate while loop until every second of web history has been traversed
    while init <= dates[-1]:
        ended = False
        for i in range(startindex,len(dates)): #search forward from init until startindex is found
            if dates[i] - init >= timedelta(0):
                startindex = i
                break
        #search forward from the endindex of the last line for current line's endindex
        for i in range(endindex,len(dates)):  
            if dates[i] - init >= difference:
                endindex = i
                counter[init] = endindex - startindex
                init += timedelta(0,1)
                ended = True
                break
        #if search concludes without finding endpoint, either not enough entries for a 60-minute window
        #or the search is reaching the last hour of web traffic. 
        if ended == False: 
            endindex = len(dates)
            counter[init] = endindex - startindex
            init += timedelta(0,1)
            endindex = startindex
    return counter

def find_features(ips, requests,dates):
    """Utilize a heapq sort to pull top 10 largest values from dictionaries. Heapq is
    """
    
    counter = process_dates(dates)
    #top_ips = heapq.nlargest(10, ips, key=ips.get)
    #top_requests = heapq.nlargest(10, requests, key=requests.get)
    
    top_ips = find_top_values(ips)
    top_requests = find_top_values(requests)
    top_dates = find_top_values(counter)
    #heapq.headpop() is used to pop off the bottom of the heap to populate
    #a top 10 list of values for added speed on larger data structures
    temp1 = [[i[0], i[1]] for i in top_ips]
    temp2 = [i[0] for i in top_requests]
    temp3 = [[i[0].strftime("%d/%b/%Y:%H:%M:%S -0400"), i[1]] for i in top_dates]
    return temp1, temp2, temp3

def find_top_values(temp):
    """
    Implement heap sort using the heappop method to iteratively populate
    a list of top 10 values from an input dictionary. 
    """
    #Utilize heap sort for additional speed on larger data structures    
    heap = [(-value, key) for key, value in temp.items()]
    heapq.heapify(heap)
    topelements = []
    if len(temp) >= 10:   #check if there are 10 or more 
        for i in range(10):
            top = heapq.heappop(heap)
            topelements.append((top[1], -top[0]))
            heapq.heapify(heap)
    else:   #if there are less than 10 elements in the input dictionary
        for i in range(len(temp)):
            top = heapq.heappop(heap)
            topelements.append((top[1], -top[0]))
            heapq.heapify(heap)
    return topelements

def check_error(code):
    """
    Check for HTTP error codes
    """
    
    if code in ['302', '304', '400', '401', '403', '404', '500', '501']:
        return True
    else:
        return False
    
def check_time_diff(warning, date, ip):
    """
    Pulls benchmark date for IP address from dictionary of existing warnings and
    evaluates if the time difference from a given time is greater than 20 seconds.
    """
    
    if warning[ip][1] != timedelta(0): #if value set to timedelta(0), no existingwarnings
        if warning[ip][1] - date <= timedelta(0,20):
            return True
        else:
            return False
    else:
        return False
        
def check_blocked(blocked, ip, date):
    """
    Pulls benchmark date for IP address from dictionary of existing blocks and
    evaluates if 5 minutes have elapsed since the start of the block. If not,
    current successful or failed request will be logged.
    """
    
    blockwindow = timedelta(0,300)
    if blocked[ip] != timedelta(0): #if value set to timedelta(0), no existing blocks
        if date - blocked[ip] < blockwindow:
            return True
        else:
            return False
    else:
        return False
        
def check_warning(warning, ip, sample, blocked, date, code):
    """
    Checks for failed logins and applies policy for blocked users to check if user
    has had 3 subsequent failed logins within 20 seconds of a failed login by one user.
    warning is a dictionary of lists where IP addresses are keys:
    1st element is the warning count,
    2nd element is the start of the warning time check. 
    """
    
    if check_error(code): #check if there's a failed login
        
        if ip in warning.keys(): #verify if ip has been initialized in the dictionary
            
            if warning[ip][0] > 0: #check if there's an existing warning count for ip
                
                if check_time_diff(warning, date, ip):
                    #add a warning for the ip if within 20 seconds of prev warning
                    warning[ip][0] += 1
                    
                    if warning[ip][0] == 3: #verify three warnings
                        blocked[ip] = date #set the block period start time
                        warning[ip][0] = 0 #reset warning count
                        warning[ip][1] = timedelta(0) #reset warning start time
                        
                else: #20 seconds have passed, reset the ip variables
                    warning[ip][1] = timedelta(0)
                    warning[ip][0] = 0
                    
            else: #warning count was previously reset -- add a warning and start the warning date check
                warning[ip][1] = date
                warning[ip][0] = 1
                
        else: #ip not in the warnings dictionary, create new entry and start a warning date check
            warning[ip] = [1, date]
    return warning, blocked

def find_blocked(date, code, ip, sample, blocked, warning, output):
    """blocked is a dictionary of lists where an IP key contains:
    1st element: All lines to be outputted to the txt file
    2nd element: Time from when the 5 minute block started -- if no block, set to timedelta(0)
    Applies blocked user policy where all subsequent logins from a blocked IP address are logged
    since the third failed log in from the same user over a period of 20 seconds. 
    """
    
    if ip in blocked.keys():    #checks if IP address exists in dictionary
        
        if check_blocked(blocked, ip, date):
            #checks if IP address is currently blocked, appends the text line if True
            output.append(sample)
            
        else: #block is inactive/has expired, reset block and send line to be checked for failed login
            blocked[ip] = timedelta(0)
            warning, blocked = check_warning(warning, ip, sample, blocked, date, code)

    else:   #no block entry for IP, proceed to warning check 
        warning, blocked = check_warning(warning, ip, sample, blocked, date,code)
    return blocked, warning, output

def to_file(temp, formattype,filepath):
    """
    Handles printing from a list to a txt file. formattype controls the output type,
    filepath holds the folder destination and file name.
    """
    
    if formattype == 0: #One value per line
        with open(filepath, 'w') as file_handler:
            for item in temp:
                file_handler.write("{}\n".format(item))
    elif formattype == 1: #Two values per line
        with open(filepath, 'w') as file_handler:
            for item in temp:
                file_handler.write("{}\n".format(str(item[0]) + ',' + str(item[1])))

def log_error(errorlog):
    """
    Logs Python exceptions and logs their output to an error log list for further review
    """
    exc_type, exc_value, exc_traceback = sys.exc_info()
    lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
    errorlog.append((lines, datetime.now()))
    return errorlog
