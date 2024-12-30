from .__version__ import __version__
import subprocess
import json
import os
from urllib.parse import urlparse
from b_hunters.bhunter import BHunters
from karton.core import Task
import re
import os
from bson.objectid import ObjectId

def parse_xray(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)

    def remove_keys(obj):
        if isinstance(obj, dict):
            for key in ["snapshot", "create_time", "Author"]:
                if key in obj:
                    del obj[key]
            for value in obj.values():
                remove_keys(value)
        elif isinstance(obj, list):
            for item in obj:
                remove_keys(item)

    remove_keys(data)
    return json.dumps(data, indent=4)

class xraym(BHunters):
    """
    B-Hunters Xray developed by Bormaa
    """

    identity = "B-Hunters-xray"
    version = __version__
    persistent = True
    filters = [
        {
            "type": "subdomain", "stage": "new"
        }
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
    def xraycommand(self,url):
        result=[]
        result403=[]
        newurls=[]
        outputfile=self.generate_random_filename()

        try:
            try:
                output = subprocess.run(["./xray/xray","ws","--basic-crawler",url,"--json-output",outputfile],capture_output=True,text=True,timeout=7200, cwd='/')  
            except subprocess.TimeoutExpired:
                self.log.warning(f"Xray process timed out for URL: {url}")
            if os.path.exists(outputfile):
                result=parse_xray(outputfile)
                
                    
                os.remove(outputfile)

        except Exception as e:
            self.log.error("Error happened with xray")
            self.log.error(e)

            raise Exception(e)

        return result
                
    def scan(self,url):        
        result=self.xraycommand(url)
        return result
        
    def process(self, task: Task) -> None:
        source = task.payload["source"]
        url =task.payload["data"]
        # if source == "producer":
        #     url = task.payload_persistent["domain"]
        # else:
        #     url = task.payload["data"]
        
        self.log.info("Starting processing new url")
        domain = re.sub(r'^https?://', '', url)
        domain = domain.rstrip('/')
        self.log.info(domain)
        self.scanid=task.payload_persistent["scan_id"]
        report_id=task.payload_persistent["report_id"]
        self.update_task_status(domain,"Started")
        try:
            result=self.scan(url)
            self.waitformongo()
            collection=self.db["reports"]
            if result !=[]:
                xraydata= json.loads(result)
                discorddata=[]
                for item in xraydata:
                    output = []
                    if item["detail"]["addr"]:
                        output.append(f"addr: {item['detail']['addr']}")
                    if item["detail"]["payload"]:
                        output.append(f"payload: {item['detail']['payload']}")
                    if item["plugin"]:
                        output.append(f"plugin: {item['plugin']}")
                    discorddata.append(", ".join(output))
                discorddata="\n".join(discorddata)
                
                max_length = 4000
                discorddata_chunks = [discorddata[i:i + max_length] for i in range(0, len(discorddata), max_length)]
                
                for idx, chunk in enumerate(discorddata_chunks):
                    title = f"{self.identity} Results for {domain} (Part {idx + 1})" if len(discorddata_chunks) > 1 else f"{self.identity} Results for {domain}"
                    self.send_discord_webhook(title, chunk, "main")
                if self.db.client.is_primary:
                    update_result =collection.update_one({"_id": ObjectId(report_id)}, {"$push": {f"Vulns.Xray": {"$each": xraydata}}})

                    if update_result.modified_count == 0:
                        self.log.warning(f"Update failed for domain {domain}. Document not found or no changes made.")
                        # Optionally, you can check if the document exists
                        if collection.count_documents({"Domain": domain}) == 0:
                            self.log.error(f"Document for domain {domain} does not exist in the collection.")
                        else:
                            self.log.info(f"Document exists for {domain}, but no changes were made. Possibly duplicate data.")
                    else:
                        self.log.info(f"Successfully updated document for domain {domain}")
                else:
                    raise Exception("MongoDB connection is not active. Update operation aborted.")

            self.update_task_status(domain,"Finished")
        except Exception as e:
            self.update_task_status(domain,"Failed")
            raise Exception(e)
            self.log.error(e)
