import urllib2
import BeautifulSoup
import re
import sqlite3
import os

###################################################################
# Global Variables : for crawling                                 #
###################################################################
BASE_URLS = ['https://malwr.com/analysis/']
USER_AGENTS = ['Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)']

REG_EXP = {
	'reportURL':r'[a-zA-Z0-9]{43}', 
	'harmfulDegree':r'[0-9]{0,2}[/][0-9]{2}',
	}
###################################################################

def getHTML(url) : 
	for user_agent in USER_AGENTS :
		req = urllib2.Request(url)
		req.add_header('User-agent', user_agent)
		response = urllib2.urlopen(req)

		# add to handle 503 error
		page = response.read()
		return page

def reportCrawling() :
	print "Start to crawl report Urls..."

	for url in BASE_URLS :
		page = getHTML(url)

		bs = BeautifulSoup.BeautifulSoup(page)
		temp = bs.findAll('table', attrs={'class':'table table-striped'})

		reports = temp[0]
		reports = reports.findAll('tr')

		for report in reports :
			report = str(report)

			harmfulDegree = re.findall(REG_EXP['harmfulDegree'], report)
			if len(harmfulDegree) > 0 :
				harmfulDegree = int(harmfulDegree[0].split('/')[0])
			else :
				continue

			reportURL = re.findall(REG_EXP['reportURL'], report)
			if len(reportURL) > 0 :
				reportURL = reportURL[0]

			if harmfulDegree > 0 :
				query = "INSERT INTO reports VALUES('" + reportURL + "', '" + str(harmfulDegree) + "', 'false')"
				dbHandler(query)

def dbHandler(query) :
	conn = sqlite3.connect('iocdb.db')
	cur = conn.cursor()
	cur.execute(query)
	rows = cur.fetchall()
	conn.commit()
	conn.close()

	return rows

def makeIOC() :
	print "Start to make indicator of compromise of each report..."

	query = "SELECT reportURL FROM reports WHERE makeIocFlag = 'false'"
	rows = dbHandler(query)
	url = BASE_URLS[0]

	for row in rows :
		page = getHTML(url + row[0])
		print page

	return

def main() :
	reportCrawling()
	makeIOC()
	
if __name__ == '__main__':
	main()