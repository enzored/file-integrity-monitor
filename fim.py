import os, hashlib, json
import smtplib,time
from logging.handlers import RotatingFileHandler

#enzored: User just needs to fill in the following conf params. Use ['*'] if you want to monitor all files
fileExtensions = ['.php', '.jpg', '.docx']
dirsToMonitor = ['D:/Documents']
resultsdir = 'D:/temp'
emailfrom = "fim@yourdomain.com"
emailto = "myemail@yourdomain.com"
smtpserver = 'localhost'
#end user conf

resultsfilepath = os.path.join (resultsdir, 'fim_results.json')
previous_results = {}
current_results = {}

#enzored: this handler is just used to rotate file results
handler = RotatingFileHandler(resultsfilepath, backupCount=10)

def saveRun():
    if os.path.isfile(resultsfilepath):
        handler.doRollover()
    with open(resultsfilepath, 'w') as f:
        json.dump(current_results, f)

def loadPreviousrun():
    global previous_results
    if os.path.isfile(resultsfilepath):
        with open(resultsfilepath) as f:
            try:
                previous_results = json.load(f)
            except ValueError, e:
                print 'File does not contain a valid JSON object. This file will be overwritten after this run.'
                previous_results = {}
            return True

#enzored: This script is not storing passwords but calculating loads file hashes. Yes MD5 is enough in this case.
#also much faster than SHA1.
def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def find_files(directories, fileExtensions):
    if '*' in fileExtensions: monitorAllFiles= True
    else: monitorAllFiles= False
    for directory in directories:
        for root, dirs, files in os.walk(directory):
            for basename in files:
                if not monitorAllFiles:
                    if basename.endswith(tuple(fileExtensions)):
                        filename = os.path.join(root, basename)
                        yield filename
                else:
                     filename = os.path.join(root, basename)
                     yield filename

def main():
    sendResults = True
    starttime = time.strftime("%Y-%m-%d %H:%M:%S")
    loadPreviousrun()
    for filename in find_files(dirsToMonitor, fileExtensions):
        filehash = md5(filename)
        current_results[filename]=filehash

    previous_keys = set(previous_results.keys())
    current_keys = set(current_results.keys())
    intersect_keys = previous_keys.intersection(current_keys)
    added = current_keys - previous_keys
    removed = previous_keys - current_keys
    modified = {o : (previous_results[o], current_results[o]) for o in intersect_keys if previous_results[o] != current_results[o]}
    same = set(o for o in intersect_keys if previous_results[o] == current_results[o])
    endtime = time.strftime("%Y-%m-%d %H:%M:%S")

    if len(added) == 0 and len(removed) == 0 and len(modified.keys()) == 0:
        sendResults =False

    output = "File Integrity Monitoring run results\n\n"
    output += "Start Time " + starttime + "\n"
    for file in added: output = ''.join((output, "[+] " + file + " was added.\n"))
    output += "\n"
    for file in removed: output = ''.join((output, "[-] " + file + " was deleted.\n"))
    output += "\n"
    for filename, (hashbefore,hashafter) in modified.iteritems(): output = ''.join((output,"[!] " + filename + " has changed from " + hashbefore + " to ", hashafter + "\n"))
    output += "\n"
    output += "End Time " + endtime
    print output
    saveRun()
    if sendResults:
        sendEmail(starttime,output)

def sendEmail(starttime, text):
    from email.mime.text import MIMEText
    msg = MIMEText(text)
    msg['Subject'] = starttime + ' FIM'
    msg['From'] = emailfrom
    msg['To'] = emailto
    s = smtplib.SMTP(smtpserver)
    s.sendmail(emailfrom, [emailto], msg.as_string())
    s.quit()

if __name__ == "__main__":
    main()