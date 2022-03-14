'''
DESCRIPTION:

    This program is used to crawl the following urls for CVE information:

    -https://www.fortigaurd.com/encyclopedia?type=ips
    -https://www.fortigaurd.com/encyclopedia?type=forticlientvuln

    If any CVE references are discovered, the CVE name, vuln name, and vuln
    description are collected stored in a mongodb database.

TO RUN:

    Just the script:
        python alienvault_interview_crawler.py

    In docker container:
        build -t alienvault_interview_test .
        docker run alienvault_interview_test

BREIF DESCRIPTION OF PROBLEM SOLVING METHODOLOGY:
    -Research and recon on urls to be crawled (View page, inspect elements
     of interest, etc).
    -Research and select tools and packages to be used.
    -Write core code (Crawl each page for entries, crawl each entry for CVE info)
    -Make code more efficient by asyncronously crawling entries (Improved from
     10-12 seconds per page to 5-8 seconds per page).
    -Store CVE info in MongoDB asyncronously.
    -Write Dockerfile and deploy code in Docker container.
    -Testing (Discovered some interesting edge cases, such as the webpage
     not being able to handle to many asyncronous requests and certain
     CVE descriptions containing unexpected input).
    -Polish up documentation

CREATED BY: Matt Kilcher

CREATED DATE: 3/7/2022
'''

#Imports for retrieving and parsing webpages
import requests
import lxml
from bs4 import BeautifulSoup as soup

#Imports for asyncronous features
import asyncio
from concurrent.futures import ThreadPoolExecutor

#Imports for database features
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import UpdateOne

#Misc imports
import time

'''
This function is used to retrieve a page of vuln entries from the
selected url.

Inputs:
-The root url of the site to be crawled.
-The number of the page currently being processed.
-The headers for the request.

Outputs: If there are still pages to be processed, returns the data found on
the page. Otherwise, returns 'None' to signal all pages for current root url
have been processed.
'''
def get_and_parse_page(root_url, page_num, headers):

    attempts = 0

    while attempts < 3:
        url = root_url + str(page_num)

        response = requests.get(url, headers = headers)
        parsed_response = soup(response.content, 'lxml')
        response.close()

        #Isolate data of interest
        data = parsed_response.find('div',{'class':'results'}).find_all('a')

        if data != []:
            break

        attempts += 1
        time.sleep(3)

    if attempts == 3:
        return None

    return data

'''
This function is used to handle the asyncronous execution of the
'get_and_parse_entry' function.

Inputs:
-Data of interest obtained from 'get_and_parse_page'
-The headers for the request.

Outputs: None
'''
async def get_and_parse_entry_async(data, headers):

    #Create thread pool and concurrently call
    #'get_and_parse_entry' for each anchor found in 'data'.

    #Run with at most 5 threads, or data can't be correctly retreived.
    with ThreadPoolExecutor(max_workers=5) as executor:

        with requests.Session() as session:
            loop = asyncio.get_event_loop()

            tasks = [
                loop.run_in_executor(
                    executor, get_and_parse_entry, *(session, anchor, headers)
                )
                for anchor in data
            ]

            #Await response from all tasks
            for entry_response in await asyncio.gather(*tasks):
                pass

'''
This function is used to retrieve and parse a given vuln entry.

Inputs:
-Async session to be used.
-HTML anchor to pull the entry link from.
-The headers for the request.

Outputs: None
'''
def get_and_parse_entry(session, anchor, headers):

    #If anchor is within the nav bar, the bottom of the page has been reached
    #and that anchor should not be processed
    if anchor.find_parent('nav') == None:
        entry_url = 'https://www.fortiguard.com' + anchor['href']

        print("Working on entry: " + entry_url + "...")

        try:
            entry_response = requests.get(entry_url, headers = headers)
            parsed_entry_response = soup(entry_response.content, 'lxml')
            entry_response.close()

            entry_data = parsed_entry_response.find('section',{'class':'ency_content'})

            if entry_data != None:
                entry_anchors = entry_data.find_all('a')

                #Search entry for CVE information
                for entry_anchor in entry_anchors:
                    get_CVE_info(entry_anchor, entry_data)

            #If data recieved is corrupted, skip entry and log error
            else:
                print("Entry on page " + str(page_num) + " could not be retrieved, skipping entry")
                errors.append(entry_url)

        except:
            print("Entry on page " + str(page_num) + " could not be retrieved, skipping entry")
            errors.append(entry_url)

'''
This function is used to search for any refrences to CVEs in the given entry.

Inputs:
-HTML anchor to pull the CVE name from.
-Data of interest obtained from 'get_and_parse_entry'

Outputs: Appends CVE entry (name and description) to entry batch, to be
added to database.
'''
def get_CVE_info(anchor, entry_data):


    anchor_text = anchor.contents[0]

    #If anchor contains CVE information, signifies entry has a "CVE Refrences"
    #section, and CVE info should be collected.
    if anchor_text.startswith("CVE"):

        #Get vuln name
        name = entry_data.find('h2',{'class':'title'}).contents[0]

        #Get and format vuln description
        description = entry_data.find('p').contents

        for i, content in enumerate(description):

            #In case of line break, remove.
            if str(content) == '<br/>':
                del description[i]
                continue

            #In case of link in description, replace href with text.
            if str(content).startswith("<a href="):
                description[i] = description[i].contents[0]
                continue

            #In case of unexpected html, convert to string.
            if str(content).startswith("<") and str(content).endswith(">"):
                description[i] = str(description[i])

        description_formatted = ' '.join(description)

        #Prepare entry
        entry = {anchor_text: {'name': name, 'description': description_formatted}}
        entry_batch.append(entry)

'''
This function is used to update the database with new entry batches asyncronously.

Inputs:
-Batch of CVE entries to be pushed to the database.

Outputs: Bulk updates database with new entries.
'''
async def save_entries_async(entry_batch):

    BATCH_SIZE = 500

    updates = list()

    #Format each entry for bulk update
    for entry in entry_batch:
        filter_ = {
            "_id": 1
        }
        update_ = {
            "$set": entry,
        }

        update = UpdateOne(filter = filter_, update=update_, upsert=True)
        updates.append(update)

        #If updates exceeds set batch size, push a bulk update.
        if len(updates) >= BATCH_SIZE:
            await collection.bulk_write(updates, ordered=False)
            updates = list()

    #Push any remaining entires.
    if len(updates) > 0:
        await collection.bulk_write(updates, ordered=False)

'''
Main loop, runs until all urls in root_urls have been crawled.
'''

#Set constants

#URLs to be processed
root_urls = ["https://www.fortiguard.com/encyclopedia?type=ips&page=", "https://www.fortiguard.com/encyclopedia?type=forticlientvuln&page="]

user_agent_list = [
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
]

ua_rotate = 0

#Error list for any entries that were incorrectly processed (DEBUG)
errors = []

entry_batch = []

#Attempt to connect to database
try:
    mongo_url = "mongodb+srv://admin:admin@alienvault-interview-cl.mqngr.mongodb.net/alienvault_interview_db?retryWrites=true&w=majority"
    client = AsyncIOMotorClient(mongo_url)
    client.get_io_loop = asyncio.get_running_loop

    db = client.get_database("alienvault_interview_db")
    collection = db.get_collection("alienvault_interview_collection")
except:
    print("Couldn't connect to database...")
    exit()

for root_url in root_urls:

    page_num = 1 #26 #473

    while(True): #page_num <= 500

        #Select new user agent from 'user_agent_list' every 20 pages.
        #Aids in avoiding web crawling detection.
        if page_num % 20 == 0:
            ua_rotate += 1
            if ua_rotate > 4:
                ua_rotate = 0
            print("User agent rotated to " + user_agent_list[ua_rotate] + "...")

        headers = {
          'User-Agent': user_agent_list[ua_rotate]
        }

        data = get_and_parse_page(root_url, page_num, headers)

        if data == None:
            print("Crawled all webpages with this url")
            break

        print("Working on page " + str(page_num) + "...")

        asyncio.run(get_and_parse_entry_async(data, headers))

        #Update database every 10 pages.
        if page_num % 10 == 0:
            asyncio.run(save_entries_async(entry_batch))
            print(len(entry_batch))
            entry_batch = []

        page_num += 1

print(errors)
