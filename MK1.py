import re
from matplotlib import pyplot as plt
import numpy as np
import pandas as pd
from sklearn import tree
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from tld import get_tld, is_tld
import seaborn as sns
import firebase_admin
from firebase_admin import firestore
from firebase_admin import credentials
import urllib.request

cred = credentials.Certificate('fir-3e64a-firebase-adminsdk-q37a4-356dfa0556.json')
app = firebase_admin.initialize_app(cred)
db = firestore.client()

while True:
    
    docs = db.collection('URL').get()
    for doc in docs:
        b = doc.get('url')
    url = b
    try:
        status_code = urllib.request.urlopen(url).getcode()
        website_is_up = status_code == 200
        if website_is_up:

            data = pd.read_csv('finaldataset.csv')
            data2=data.copy()


            data2['url'] = data2['url'].replace('www.', '', regex=True)

            data2.head(20)
            data2['url_len'] = data2['url'].apply(lambda x: len(str(x)))
            def process_tld(url):
                try:

                    res = get_tld(url, as_object = True, fail_silently=False,fix_protocol=True)
                    pri_domain= res.parsed_url.netloc
                except :
                    pri_domain= None
                return pri_domain

            data2['domain'] = data2['url'].apply(lambda i: process_tld(i))
            feature = ['@','?','-','=','.','#','%','+','$','!','*',',','//']
            for a in feature:
                data2[a] = data2['url'].apply(lambda i: i.count(a))
            def abnormal_url(url):
                hostname = urlparse(url).hostname

                hostname = str(hostname)

                match = re.search(hostname, url)
                if match:

                    return 1
                else:

                    return 0

            data2['abnormal_url'] = data2['url'].apply(lambda i: abnormal_url(i))
            def httpSecure(url):
                htp = urlparse(url).scheme

                match = str(htp)
                if match=='https':

                    return 1
                else:

                    return 0
            data2['https'] = data2['url'].apply(lambda i: httpSecure(i))
            def digit_count(url):
                digits = 0
                for i in url:
                    if i.isnumeric():
                        digits = digits + 1
                return digits
            data2['digits']= data2['url'].apply(lambda i: digit_count(i))
            def letter_count(url):
                letters = 0
                for i in url:
                    if i.isalpha():
                        letters = letters + 1
                return letters
            data2['letters']= data2['url'].apply(lambda i: letter_count(i))
            def Shortining_Service(url):
                match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                                'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                                'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                                'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                                'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                                'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                                'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                                'tr\.im|link\.zip\.net',
                                url)
                if match:
                    return 1
                else:
                    return 0
                
            data2['Shortining_Service'] = data2['url'].apply(lambda x: Shortining_Service(x))
            def having_ip_address(url):
                match = re.search(
                    '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                    '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
                    '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                    '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
                    '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
                    '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)
                if match:
                    return 1
                else:
                    return 0
            data2['having_ip_address'] = data2['url'].apply(lambda i: having_ip_address(i))
            X = data2.drop(['url','label','domain'],axis=1)
            y = data2['label']

            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=2)



            def URL_Converter(urls):
                data= pd.DataFrame()
                data['url'] = pd.Series(urls)

                
                data['url_len'] = data['url'].apply(lambda x: len(str(x)))
                data['domain'] = data['url'].apply(lambda i: process_tld(i))
                feature = ['@','?','-','=','.','#','%','+','$','!','*',',','//']
                for a in feature:
                    data[a] = data['url'].apply(lambda i: i.count(a))  
                data['abnormal_url'] = data['url'].apply(lambda i: abnormal_url(i))
                data['https'] = data['url'].apply(lambda i: httpSecure(i))
                data['digits']= data['url'].apply(lambda i: digit_count(i))
                data['letters']= data['url'].apply(lambda i: letter_count(i))
                data['Shortining_Service'] = data['url'].apply(lambda x: Shortining_Service(x))
                data['having_ip_address'] = data['url'].apply(lambda i: having_ip_address(i))
                X = data.drop(['url','domain'],axis=1)
                
                return X

            print(b)


            X_predict1 = f"{b}"

            test_data=URL_Converter(X_predict1)
            models = SVC(kernel='rbf',gamma=0.01)
            models.fit(X_train, y_train)
            pred = models.predict(test_data)

            for i in pred:
                if i == 1:
                    a = "Safe"
                else:
                    a = "Spam"
            print(a)


            doc_ref = db.collection(u'result').document(u'result')
            doc_ref.set({
                u'result' : f'{a}'
                })
    except:
            doc_ref = db.collection(u'result').document(u'result')
            doc_ref.set({
                u'result' : u'Spam/Invalid'
                })
            print("Spam/Invalid")
