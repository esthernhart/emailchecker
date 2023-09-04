import os
from os import system
import sys, subprocess
import email
import imaplib
import re
import dns.resolver
import platform
plat = platform.system()

def clear():
    if plat == 'Windows':
        os.system('cls')
    else:
        os.system('clear')

imap_url = 'imap.gmail.com'
mail = imaplib.IMAP4_SSL(imap_url)
regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'  

def view_whitelist():
     with open('whitelist.txt', 'r') as f:
          view = f.read()
          print()
          print(view)
          print()
          input("Press [Enter] to continue.") 

def add_whitelist():
    with open('whitelist.txt', 'a+') as f:

        f.seek(0)
        data = f.read(100)
        if len(data) > 0:
             f.write("\n")

        add = input("Enter the new domain to add on whitelist: ")
        f.write(add)

        print()
        print("Successfully add new domain")
        input("Press [Enter] to continue.") 
        

def remove_whitelist():

    remove = input("Enter the domain you would like to remove: ")
    with open('whitelist.txt', 'r') as f:
         lines = f.readlines()

    with open('whitelist.txt', 'w') as f:
         for line in lines:
              if line.strip("\n") != remove:
                   f.write(line)

    system('cls')
    header()
    view_whitelist()

def mail_checker():
     status, data = mail.select("INBOX")

     messages = int(data[0])
     count = messages

     list_sender = []
     result_email = []

     whitelist_file = open('whitelist.txt', 'r')
     whitelist_list = whitelist_file.readlines()

     validated = []
     not_duplicated = [x for n, x in enumerate(list_sender) if x not in list_sender[:n]]

     system('cls')
     for mem in range(0, len(not_duplicated)):
          if not_duplicated[mem].count('@') != 1:
               result_email.append(not_duplicated[mem])
          else:
               if(re.search(regex, not_duplicated[mem])):
                    pass
               else:
                    count_vuln = 0
                    injection = ['<','script','>','/','select','*','from','where','union',' or ',' null ', 'UTF-8']
                    for check_injection in range (0, len(injection)):
                         if injection[check_injection] in not_duplicated[mem].lower():
                              count_vuln += 1
                         else:
                              pass
                    if count_vuln > 0:
                         result_email.append(not_duplicated[mem])
                    else:
                        if re.search('\.com$', not_duplicated[mem]) or re.search('\.co\.id$', not_duplicated[mem]) or re.search('\.org$', not_duplicated[mem]) or re.search('\.edu$', not_duplicated[mem]) or re.search('\.net\.id$', not_duplicated[mem]):
                            pass
                        else:
                            not_in_whitelist = 0
                            for wlist in range(0, len(whitelist_list)):
                                if whitelist_list[wlist] in not_duplicated[mem].lower():
                                    validated.append(not_duplicated[mem])
                                else:
                                    not_in_whitelist += 1
                            
                            if not_in_whitelist > 0:
                                result_email.append(not_duplicated[mem])
                            else:
                                pass
        
     print("\n\nEmail(s) that have possibility in email phishing :\n")
     if len(result_email) != 0:
        for res in range(0, len(result_email)):
            print("%s. %s" %(res+1, result_email[res]))
     else:
        print("No Invalid Email.")
                      

def mx_record():
    list_sender = []
    result_email = []

    try:
        not_duplicated = [x for n, x in enumerate(list_sender) if x not in list_sender[:n]]
        for mem in range(0,len(not_duplicated)):    
            records = dns.resolver.resolve(not_duplicated[mem], 'MX')   
            mx_re = records[0].exchange
            mx_re = str(mx_re)
    except:
         result_email.append(not_duplicated[mem])     
    
    print("\n\nEmail(s) that have possibility in email phishing :\n")
    for res in range(0,len(result_email)):
          print("%s. %s" %(res+1,result_email[res]))

# Function to get the list of emails under this label
def get_emails(result_bytes):
	msgs = [] # all the email data are pushed inside an array
	for num in result_bytes[0].split():
		typ, data = mail.fetch(num, '(RFC822)')
		msgs.append(data)

	return msgs

def view_mail():
    status, data = mail.select("INBOX")
    
    messages = int(data[0])
    count = messages
    list_sender = []

    print("\n")
    for num in range(messages, messages - count, -1):
        status, data = mail.fetch(str(num), '(RFC822)')

        for response in data:
                if isinstance(response, tuple):
                    msg = email.message_from_bytes(response[1])

                     # Store the senders email
                    # sender = msg["From"]
                    # list_sender.append(email.utils.parseaddr(sender)[1])
                    # Print Sender, Subject, Body
                    print("#%s : %s" % (messages+1-num,msg['from']))
                    print("Subject:", msg['subject'])
                    print()

def subj_mail():
    status, data = mail.select("INBOX")
    
    messages = int(data[0])
    count = messages

    whitelist_file = open('whitelist.txt', 'r')
    whitelist_list = whitelist_file.readlines()
    list = []


    print("\n")
    count_subject = 1
    for num in range(messages, messages - count, -1):
        status, data = mail.fetch(str(num), '(RFC822)')
        c = 0
        nc = 0
        count_wl = 0
        for response in data:
                if isinstance(response, tuple):
                    msg = email.message_from_bytes(response[1])
                    
                    subject = msg['subject']
                    sender = msg['from']

                    #remove the \n
                    domain_wl = []

                    for line in whitelist_list:
                         domain_wl.append(line.strip())
                    #print(domain_wl)

                    for m in range(0, len(domain_wl)):
                         if domain_wl[m] in sender:
                              #print("WL")
                              count_wl += 1
                         else:
                              #print ("NWL")
                              pass

                    if (re.search('UTF-8', subject)) or (re.search('utf-8', subject)) or (re.search('=', subject)):
                         c = c + 1
                    else:
                        pass
                                
            

                    if (c > 0) and (count_wl == 0):
                        print("%s" % sender)
                        print(count_subject, "- Subject:", msg['subject'])
                        print("")
                        count_subject += 1
                    else:
                        pass

clear()
logo = """
    ______                   _  __   ______ __                 __              
   / ____/____ ___   ____ _ (_)/ /  / ____// /_   ___   _____ / /__ ___   _____
  / __/  / __ `__ \ / __ `// // /  / /    / __ \ / _ \ / ___// //_// _ \ / ___/
 / /___ / / / / / // /_/ // // /  / /___ / / / //  __// /__ / ,<  /  __// /    
/_____//_/ /_/ /_/ \__,_//_//_/   \____//_/ /_/ \___/ \___//_/|_| \___//_/     
                                                                               
                                2023
"""

def header():
    print(logo)
    print()
    print("======================================================================")

def menu():
    print()
    print("[1] View all incoming email on inbox [From and Subject]")
    print("[2] View current whitelist")
    print("[3] Add new domain on whitelist")
    print("[4] Remove domain on whitelist")
    print("[5] Email Header Check")
    print("[6] Check email header with mxrecord")
    print("[7] Quit")
    print()
    print("======================================================================")

def login():
    print()
    username = input("Please input your email: ")
    password = input("Please input your password: ")
    try:
        mail.login(username, password)
    except:
        print("login failed")
        input("Press [Enter] to exit.")
        exit() 

if __name__ == '__main__':
    while True:
        print(logo)
        print()
        #print("=====================================================================")
        print("===============================  Menu  ================================")
        menu()
        option = int(input("Option : "))
        if option == 1:
            system('cls')
            header()
            #print("=====================================================================")
            print("=                     View All Incoming Email                        =")
            print("======================================================================")
            login()
            clear()
            view_mail()
            clear()
        elif option == 2:
            system('cls')
            header()
            print("=                     View Current Whitelist                         =")
            print("======================================================================")
            view_whitelist()
            clear()
        elif option == 3:
            system('cls')
            header()
            print("=                      Add New Whitelist Domain                      =")
            print("======================================================================")
            print()
            print("Current Domain that listed on whitelist")
            view_whitelist()
            add_whitelist()
            clear()
        elif option == 4:
            system('cls')
            header()
            print("=                     Remove Whitelist Domain                        =")
            print("======================================================================")
            print()
            print("Current Domain that listed on whitelist")
            view_whitelist()
            remove_whitelist()
            clear()
        elif option == 5:
            system('cls')
            header()
            print("=                        Email Header Check                          =")
            print("======================================================================")
            login()
            mail_checker()
            input("Press [Enter] to contiue check on the email subject.")
            subj_mail()
            input("Press [Enter] to continue.")
            clear()
        elif option == 6:
            system('cls')
            login()
            system('cls')
            mx_record()
            input("Press [Enter] to continue.")
            clear()
        elif option == 7:
            print("Thankyou for using this program")
            clear()
            exit()
        else:
            print("Invalid")
            input("Press [Enter] to continue.") 