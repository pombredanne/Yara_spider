#coding = utf-8
#Filename:Yara_Generator_spider.py
#usefor: http://www.yara-generator.net  spider
#time: 2016-01-26
#yuc

import re
import os
import sys
import urllib2
import urllib
#import argparse

class YaraGenerator_spider:
	def __init__(self):
		self.sourceUrl = 'http://www.yara-generator.net'
		if len(sys.argv) < 2:
			print 'Enter the path you want saved'
			sys.exit(1)
		else:
			self.SavePath = sys.argv[1]

	def ReadHtml(self,surl):
		req_header = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
		'Accept':'text/html;q=0.9,*/*;q=0.8'
		}
		req_timeout = 5
		req = urllib2.Request(surl,None,req_header)		
		response = urllib2.urlopen(req,None,req_timeout)
		html = response.read()
		return html 

	def ParseHtmlList(self):		
		Rulesurl = 'http://www.yara-generator.net/rules'
		Ruleshtml = self.ReadHtml(Rulesurl)
		#malicious and suspicious
		p = re.compile('<td><strong><a class="monospace" href=\"(\S+)\" target="_blank">')
		webrulesList = p.findall(Ruleshtml)
		return webrulesList
		
	def ParseDownloadUrl(self,surl):
		DownLoadHtml = self.ReadHtml(self.sourceUrl + surl)
		DownSample,mDownSample = '',''
		DownDropped = ''
		DownMemoryOpcode = ''
		pSample = re.compile('<tr><td>Sample</td><td class="center">\d+</td><td class="center"><a class="icon-search" target ="_blank" href=\"(\S+)\"')
		pDropped = re.compile('<tr><td>Dropped</td><td class="center">\d+</td><td class="center"><a class="icon-search" target ="_blank" href=\"(\S+)\"')
		pMemoryOpcode = re.compile('<tr><td>Memory Opcode</td><td class="center">\d+</td><td class="center"><a class="icon-search" target ="_blank" href=\"(\S+)\"')

		#More than one
		if DownLoadHtml.find('Simple Yara Rules for') != -1:
			pMoreMD5 = re.compile('<h4>Simple Yara Rules for (\S+):</h4>')
			mMD5 = pMoreMD5.findall(DownLoadHtml)
			#print mMD5
			pMoreOne = re.compile('<h4>Simple Yara Rules for [\S\s]*?</tbody>\n\t\t\t</table>')
			#pMoreOne = re.compile('<tr><td>Sample</td><td class="center">\d+</td><td class="center"><a class="icon-search" target ="_blank" href=\"(\S+)\"')
			mhtml = pMoreOne.findall(DownLoadHtml)
			#print mhtml
			if len(mMD5) != len(mhtml):
				print 'MD5 num error'
				sys.exit(1)
			for i in range(len(mhtml)):
				if mhtml[i].find('<tr><td>Sample') != -1:
					mDownSample = pSample.findall(mhtml[i])[0]
					#print DownSample
					self.DownLoadYaraNamedMD5(mDownSample,mMD5[i],'simple_samplerule')
				if mhtml[i].find('<tr><td>Dropped') != -1:
					if len(mDownSample) > 0:
						mDownDropped = DownSample.replace('simple_samplerule','simple_droppedrule')
					else:
						mDownDropped = pDropped.findall(mhtml[i])[0]
					#print DownDropped
					self.DownLoadYaraNamedMD5(mDownDropped,mMD5[i],'simple_droppedrule')
				if mhtml[i].find('<tr><td>Memory Opcode') != -1:
					if len(DownSample) > 0:
						mDownMemoryOpcode = DownSample.replace('simple_samplerule','simple_memorycoderule')
					else:
						mDownMemoryOpcode = pMemoryOpcode.findall(mhtml[i])[0]
					#print DownMemoryOpcode
					self.DownLoadYaraNamedMD5(mDownMemoryOpcode,mMD5[i],'simple_memorycoderule')
			
		#Only one
		else:
			pMD5 = re.compile('<td>MD5</td>\n\t*<td class="size-limit">(\w+)</td>')
			md5 = pMD5.findall(DownLoadHtml)[0]
			#print md5
			if DownLoadHtml.find('<tr><td>Sample') != -1:
				DownSample = pSample.findall(DownLoadHtml)[0]
				#print DownSample
				self.DownLoadYaraNamedMD5(DownSample,md5,'simple_samplerule')
			if DownLoadHtml.find('<tr><td>Dropped') != -1:
				if len(DownSample) > 0:
					DownDropped = DownSample.replace('simple_samplerule','simple_droppedrule')
				else:
					DownDropped = pDropped.findall(DownLoadHtml)[0]
				#print DownDropped
				self.DownLoadYaraNamedMD5(DownDropped,md5,'simple_droppedrule')
			if DownLoadHtml.find('<tr><td>Memory Opcode') != -1:
				if len(DownSample) > 0:
					DownMemoryOpcode = DownSample.replace('simple_samplerule','simple_memorycoderule')
				else:
					DownMemoryOpcode = pMemoryOpcode.findall(DownLoadHtml)[0]
				#print DownMemoryOpcode
				self.DownLoadYaraNamedMD5(DownMemoryOpcode,md5,'simple_memorycoderule')


	def DownLoadYaraNamedMD5(self,surl,md5,yaratype):
		URL = self.sourceUrl + surl + '?download=1'
		localname = self.SavePath + '\\'+ md5 + '_' + yaratype + '.yara'
		if os.path.exists(self.SavePath) == False:
			os.makedirs(self.SavePath)
		if os.path.exists(localname) == False: #same
			print localname
			savefile = self.ReadHtml(URL)
			fo = open(localname,'wb')
			fo.write(savefile)
			fo.close()
		else:
			print localname+' have already download'

def main():
	print "Parse and Download from Yara_Generator"
	print "use example: Yara_Generator.py c:\\test"
	mspider = YaraGenerator_spider()
	RuleList = mspider.ParseHtmlList()
	for i in RuleList:
	#	print i
		mspider.ParseDownloadUrl(i)
	#mspider.ParseDownloadUrl('/rules/103')

			


if __name__ == '__main__':
    main()
