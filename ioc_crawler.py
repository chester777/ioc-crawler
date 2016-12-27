import urllib2
import BeautifulSoup
import re
import sqlite3
import os
import datetime
from xml.etree.ElementTree import Element, dump
from xml.etree.ElementTree import ElementTree

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

###################################################################
# Global Variables : for ioc making                               #
###################################################################

IOC_STORED_PATH = "./iocs/"

###################################################################

def getHTML(url) : 
	for user_agent in USER_AGENTS :
		req = urllib2.Request(url)
		req.add_header('User-agent', user_agent)
		response = urllib2.urlopen(req)

		# add to handle 503 error later
		page = response.read()
		return page

def reportCrawling() :
	print "Start to crawl report Urls..."

	for url in BASE_URLS :
		page = getHTML(url)

		bs = BeautifulSoup.BeautifulSoup(page)
		reports = bs.find('table', attrs={'class':'table table-striped'})
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
				query = "SELECT * FROM reports WHERE reportURL = '" + reportURL + "'"
				row = dbHandler(query)

				if len(row) == 0 :
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

def reportParsing() :
	print "Start to make indicator of compromise of each report..."

	query = "SELECT reportURL FROM reports WHERE makeIocFlag = 'false'"
	rows = dbHandler(query)

	for url in BASE_URLS :
		for row in rows :
			page = getHTML(url + row[0])
			
			bs = BeautifulSoup.BeautifulSoup(page)

			# File Details
			fileDetails = {}
			temp = bs.find('section', attrs={'id':'file'})
			trs = temp.findAll('tr')
			for tr in trs :
				th = tr.find('th')
				td = tr.find('td')
				
				if len(th.text) > 0 :
					fileDetails[th.text.replace(' ', '')] = td.text

			# add static analysis info later
			# add behavior analysis info later
			# add network analysis info later
			# add dropped files analysis info later

			result = makeIOC(row, fileDetails)

			if result == True :
				query = "UPDATE reports SET makeIocFlag = 'true' WHERE reportURL = '" + row[0] + "'"
				dbHandler(query)
	return

def makeIOC(row, fileDetails) :

	now = datetime.datetime.now()

	ioc = Element("ioc")
	ioc.attrib["xmlns:xsi"] = "http://www.w3.org/2001/XMLSchema-instance"
	ioc.attrib["xmlns:xsd"] = "http://www.w3.org/2001/XMLSchema"
	ioc.attrib["last-modified"] = str(now)
	ioc.attrib["xmlns"] = "http://schemas.mandiant.com/2010/ioc"

	short_description = Element("short_description")
	authored_date = Element("authored_date")
	links = Element("links")
	definition = Element("definition")

	indicator = Element("Indicator")
	indicator.attrib["operator"] = "OR"

	indicatorItem = Element("IndicatorItem")
	indicatorItem.attrib["condition"] = "is"
	context_md5sum = Element("Context")
	context_md5sum.attrib["document"] = "FileItem"
	context_md5sum.attrib["search"] = "FileItem/Md5sum"
	context_md5sum.attrib["type"] = "mir"
	context_type = Element("Context")
	context_type.attrib["type"] = "md5"
	context_type.text = fileDetails["MD5"]

	indicatorItem.append(context_md5sum)
	indicatorItem.append(context_type)
	indicator.append(indicatorItem)

	indicatorItem = Element("IndicatorItem")
	indicatorItem.attrib["condition"] = "contains"
	context_fileName = Element("Context")
	context_fileName.attrib["document"] = "FileItem"
	context_fileName.attrib["search"] = "FileItem/FileName"
	context_fileName.attrib["type"] = "mir"
	context_type = Element("Context")
	context_type.attrib["type"] = "string"
	context_type.text = fileDetails["FileName"]

	indicatorItem.append(context_fileName)
	indicatorItem.append(context_type)
	indicator.append(indicatorItem)

	indicatorItem = Element("IndicatorItem")
	indicatorItem.attrib["condition"] = "is"
	context_size = Element("Context")
	context_size.attrib["document"] = "FileItem"
	context_size.attrib["search"] = "FileItem/SizeInBytes"
	context_size.attrib["type"] = "mir"
	context_type = Element("Context")
	context_type.attrib["type"] = "int"
	context_type.text = fileDetails["FileSize"].split(" ")[0]

	indicatorItem.append(context_size)
	indicatorItem.append(context_type)
	indicator.append(indicatorItem)

	definition.append(indicator)

	ioc.append(definition)
	ioc.append(short_description)
	ioc.append(authored_date)
	ioc.append(links)

	path = IOC_STORED_PATH + row[0] + ".ioc"

	ElementTree(ioc).write(path)

	return True

def main() :
	#reportCrawling()
	reportParsing()

if __name__ == '__main__':
	main()