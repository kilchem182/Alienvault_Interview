FROM python:3

ADD alienvault_interview_crawler.py /

RUN pip install requests
RUN pip install lxml
RUN pip install beautifulsoup4
RUN pip install motor
RUN pip install pymongo[srv]

CMD ["python", "./alienvault_interview_crawler.py"]
