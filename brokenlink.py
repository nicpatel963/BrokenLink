import requests
from urllib.request import urlparse, urljoin
from bs4 import BeautifulSoup
import colorama,os
from lxml import html
dir_path = os.path.dirname(os.path.realpath(__file__))
# init the colorama module
colorama.init()

GREEN = colorama.Fore.GREEN
GRAY = colorama.Fore.LIGHTBLACK_EX
RESET = colorama.Fore.RESET
RED = colorama.Fore.RED
MAGENTA=colorama.Fore.MAGENTA
# initialize the set of links (unique links)
internal_urls = set()
external_urls = set()
socialmedia_urls=set()
socialmedia_type=["facebook","twitter","linkedin","instagram","youtube"] #addmore as required....
# errors=["Not Found","This page isn't available","page isn't available","404 not found","Sorry, that page doesn’t exist!","તમે વિનંતી કરેલ પૃષ્ઠ મળ્યું નથી"] #addmore as required....
total_urls_visited = 0

def banner():
    print('--'*36+'''
     _  _    ___  _  _     _     _       _
    | || |  / _ \| || |   | |   (_)_ __ | | _____
    | || |_| | | | || |_  | |   | | '_ \| |/ / __|
    |__   _| |_| |__   _| | |___| | | | |   <\__ \\
       |_|  \___/   |_|   |_____|_|_| |_|_|\_\___/

    Coded By :~ Uday Patel     |  Nirmal Patel   |  Rohit Soni
    Twitter  :~ @mrblackstar07 |  nirmal_patel__ |  @streetofhacker
'''+'--'*36)


def is_valid(url):
    """
    Checks whether `url` is a valid URL.
    """
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)


def get_all_website_links(url):
    """
    Returns all URLs that is found on `url` in which it belongs to the same website
    """
    # all URLs of `url`
    urls = set()
    # domain name of the URL without the protocol
    domain_name = urlparse(url).netloc
    soup = BeautifulSoup(requests.get(url).content.decode(encoding="iso-8859-1"), "html.parser")
    for a_tag in soup.findAll("a"):
        href = a_tag.attrs.get("href")
        if href == "" or href is None:
            # href empty tag
            continue
        # join the URL if it's relative (not absolute link)
        href = urljoin(url, href)
        parsed_href = urlparse(href)
        # remove URL GET parameters, URL fragments, etc.
        href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
        # print(parsed_href.netloc)
        if not is_valid(href):
            # not a valid URL
            continue
        if href in internal_urls:
            # already in the set
            continue
        if domain_name not in href:
            # external link
            if href not in external_urls:
                # print(parsed_href.netloc)
                for media in socialmedia_type:
                	if media in parsed_href.netloc:
                		print(f"{MAGENTA}[~] SocialMedia link:{href}{RESET}")
                		socialmedia_urls.add(href)
                # print(f"{GRAY}[!] External link: {href}{RESET}")
                external_urls.add(href)
            continue
        # print(f"{GREEN}[*] Internal link: {href}{RESET}")
        urls.add(href)
        internal_urls.add(href)
    return urls


def crawl(url, max_urls=50):
    
    global total_urls_visited
    total_urls_visited += 1
    links = get_all_website_links(url)
    for link in links:
        if total_urls_visited > max_urls:
            break
        crawl(link, max_urls=max_urls)

def print_broken_links(socialmedia_urls):
	#this function will print broken links if any in the social media links.
	flag=False
	print("Broken links:")
	for url in socialmedia_urls:
		try:
			page=requests.get(url)
			# print(page.status_code)
			# soup = BeautifulSoup(page.content, "html.parser")
			# for msg in errors: 
			# 	if msg in str(soup):
			# 		# print(msg)
			# 		raise Exception
			if page.status_code==404:
				raise Exception
		except Exception as e:
			flag=True
			print(f"{RED}",url,f"{RESET}")

	if not flag:			
		print("0")


if __name__ == "__main__":
	import argparse
	parser = argparse.ArgumentParser(description="Link Extractor Tool with Python")
	parser.add_argument("url", help="The URL to extract links from.")
	parser.add_argument("-m", "--max-urls", help="Number of max URLs to crawl, default is 30.", default=30, type=int)
	url_inputs=[]

	banner()
	
	while True:
		print('\n1. Single URL\n2. Multiple URLs\n')
		mode=input("Enter your choice (1/2) :")
		if mode=="1" or mode=="2":
			break
		else:
			print(f"{RED}wrong input{RESET}")
	if mode == "1":
		url=input("enter url:")
		url_inputs.append(url)
	else:
		path=input("enter path of .TXT file:")
		try:
			with open(path,"r") as file:
				for url in file:
					url_inputs.append(url.strip())
		except Exception as e:
			print(str(e))
	
	# args = parser.parse_args()
	# url = args.url
	max_urls = 30 # as defined above in parser argument.  
	for url in url_inputs:
		try:
			internal_urls=set()
			external_urls=set()
			socialmedia_urls=set()
			crawl(url, max_urls=max_urls)
		except Exception as e:
			print(f"{RED} wrong url:{RESET}",url,"ERROR:",str(e))

		domain_name = urlparse(url).netloc

		if len(domain_name)>0:

			print("[+] Total Internal links:", len(internal_urls))
			print("[+] Total External links:", len(external_urls))
			print("[+] Total External social media links:", len(socialmedia_urls))
			print("[+] Total URLs:", len(external_urls) + len(internal_urls))
			print("-----------------------Check out TXT files for links at below path--------------------------")

			try:
				folder=os.path.join(dir_path, domain_name) 
				if not os.path.isdir(folder):
					os.mkdir(folder)
				# save the internal links to a file
				with open(f"{folder}/internal_links.txt", "w") as f:
					for internal_link in internal_urls:
						print(internal_link.strip(), file=f)

				# save the external links to a file
				with open(f"{folder}/external_links.txt", "w") as f:
					for external_link in external_urls:
							print(external_link.strip(), file=f)

				# save the social media links to file
				with open(f"{folder}/socialmedia_links.txt", "w") as f:
					for media_link in socialmedia_urls:
							print(media_link.strip(), file=f)
			except:
				pass
			print(f"{GRAY}{folder}\\internal_links.txt{RESET}")
			print(f"{GRAY}{folder}\\external_links.txt{RESET}")
			print(f"{GRAY}{folder}\\socialmedia_links.txt{RESET}")

			print_broken_links(socialmedia_urls)# It will print broken link if any.
