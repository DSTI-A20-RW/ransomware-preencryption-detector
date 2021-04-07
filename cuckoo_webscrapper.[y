#!/usr/bin/env python
# coding: utf-8

# In[ ]:


from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.action_chains import ActionChains
from time import sleep
from bs4 import BeautifulSoup
import os


class WebScrapper:
    
    def __init__(self,download_dir=os.getcwd()):
        
        self.chrome_options = Options()
        self.chrome_options.add_argument("--headless")
        self.chrome_options.add_argument("--window-size=1920x1080")
        self.chrome_options.add_argument("--disable-notifications")
        self.chrome_options.add_argument('--no-sandbox')
        self.chrome_options.add_argument('--verbose')
        self.chrome_options.add_experimental_option("prefs", {
                "download.default_directory": ".",
                "download.prompt_for_download": False,
                "download.directory_upgrade": True,
                "safebrowsing_for_trusted_sources_enabled": False,
                "safebrowsing.enabled": False})
        self.chrome_options.add_argument('--disable-gpu')
        # initialize driver object and change the <path_to_chrome_driver> depending on your directory where your chromedriver should be
        
        self.start_driver()

        # change the <path_to_place_downloaded_file> to your directory where you would like to place the downloaded file
        
        self.download_dir=download_dir
        
        # function to handle setting up headless download
        self.enable_download_headless()
        self.process_id=[]
        
    def start_driver(self):
        self.driver = webdriver.Chrome(options=self.chrome_options)

    def enable_download_headless(self):        
        self.driver.command_executor._commands["send_command"] = ("POST", '/session/$sessionId/chromium/send_command')
        params = {'cmd':'Page.setDownloadBehavior', 'params': {'behavior': 'allow', 'downloadPath': os.path.join(self.download_dir,'reports')}}
        self.driver.execute("send_command", params)     
        

    def go_website(self, url="https://cuckoo.ee/"):
        self.url=url
        self.driver.get(url)

    def test_drag_drop(self,file):
        self.go_website()
        
        print("This file has started ",self.driver.current_url)

       # try:
        path=os.path.join(self.download_dir,'scrapper',file)
        source1 = self.driver.find_element_by_id("file")
        
        source1.send_keys(path)
        target1 = self.driver.find_element_by_id("uploader")
        actions2 = ActionChains(self.driver)
        actions2.drag_and_drop(source1, target1).perform()

        wait = WebDriverWait(self.driver, 10)
        wait.until(lambda driver: self.driver.current_url != self.url)
        print("This file has been dropped ")

        window_after = self.driver.window_handles
        print(window_after)
        self.driver.switch_to.window(window_after[0])
        print("This file has started ",self.driver.current_url)
        sleep(1)
        sleep(1) 
        button1 = WebDriverWait(self.driver, 10).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="analysis-configuration"]/div/section/nav/ul[1]/li[3]/a/i')))
        button2 = WebDriverWait(self.driver, 10).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="start-analysis"]')))
        button1.click()
        button2.click()

        window_after = self.driver.window_handles
        print(window_after)

        self.driver.switch_to.window(window_after[0])

        print("This file has started ",self.driver.current_url)

        #need to save the number of the process
        self.process_id.append(self.driver.current_url.split("/")[-1])
        #self.quit_driver()
        

    def quit_driver(self):
        self.driver.quit()
        print("Closed driver")
        
    def files_from_summary(self):
        self.go_website("https://cuckoo.ee/analysis/")
        
        html = self.driver.page_source
        soup = BeautifulSoup(html)
        df = pd.DataFrame()
        data=[]
        for item in soup.find_all("tr"):
            row=[]
            #print(item.find_all("strong")[0].text , item.find_all("span")[3].text[6:])
            row.append(int(item.find_all("strong")[0].text))
            row.append(float(item.find_all("span")[3].text[6:]))
            data.append(row)


        df = pd.DataFrame(data,columns=['files','grade'])
        return df
        
    def go_to_summary(self,number):
        try:
            URL2="https://cuckoo.ee/analysis/{}/export/".format(number)
            # get request to target the site selenium is active on

            #self.start_driver()
            #self.enable_download_headless()
            self.driver.get(URL2)
            self.driver.get_screenshot_as_file('p1.png') 
            for n in range(1,9):
                button=self.driver.find_element_by_css_selector('#options > div > div:nth-child(3) > div > div:nth-child({}) > label'.format(n))
                button.click()

            for n in range(1,10):
                button=self.driver.find_element_by_css_selector('#options > div > div:nth-child(4) > div > div:nth-child({}) > label'.format(n))
                button.click()
            self.driver.get_screenshot_as_file('p2.png') 

            #options > div > div:nth-child(4) > div > div:nth-child(9) > label
            print("cade p3")
            # initialize an object to the location on the html page and click on it to download
            download = self.driver.find_element_by_css_selector('#options > div > div.col-md-12 > div.col-md-12.center-block > button')
            print("Element is visible? " + str(download.is_displayed()))

            download.click()
        except Exception as e:
            print("Command Line arguments processing error: " + str(e))

