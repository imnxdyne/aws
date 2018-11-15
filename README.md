# aws_cleanup.py
**Current AWS components in-scope for aws_cleanup.py:**
- EC2 instances 
- Security Groups 
- Volumes 
- Key Pairs 
- Metric Alarms
- Config Rules 
- Configuration Recorder 
- CloudFormation Stacks
- Cloud Trail 
- Cloud Watch Log Group 
- SNS Topic
- S3 Buckets 
- VPC 
- Subnets 
- Internet Gateways 
- Route Tables 
- VPC Endpoints 
- User 
- Group 
- Policy 
- Role
- Instance Profile

## Running aws_cleanup.py
- **REQUIREMENTS**  
  - Both aws_cleanup.py AND aws_cleanup_import.py files need to be in the same directory
  - aws_cleanup.py is written for Python v3.5 or greater
  - boto3 nees to be installed and configured (pip install boto3)


- **INVENTORY OF AWS COMPONENTS:**
  - **``# python3 aws_cleanup.py``**  
    Run without parameters, aws_cleanup.py displays an inventory of AWS components for all regions. 
    - Column "keep(Tag)" shows which AWS items have the tag key "keep". These AWS items are blocked from deletion when *aws_cleanup.py --del* is run.
    - Column "keep" shows which AWS items are flagged in the aws_cleanup_import.py file from being deleted when *aws_cleanup.py --del* is run (see Advanced Settings below). 

  
- **DELETING AWS COMPONENTS:**
  - **``# python3 aws_cleanup.py --del``**  
    Deletes all AWS components except for items identified as "keep" and Default VPCs. The script will first show an inventory of which AWS items will be terminated/deleted, followed by a confirmation prompt.
  - **``# python3 aws_cleanup.py --del --vpc_rebuild``**   
    Deletes all AWS components except for items identified as "keep", and deletes/recreates all Default VPCs. The recreated Default VPCs will be the same configuration as new AWS setup. The script will first list an inventory of which AWS items will be terminated/deleted, followed by a confirmation prompt.
  


## Advanced Settings:
**The file aws_cleanup_import.py contains script control settings that can be modified by the end-user.**
    
- List of AWS components that aws_cleanup.py script can inventory/delete  
  **``self.EC2 = componentDef(compName = 'EC2 instances', compDelete = True )``**  
  **``self.SecGroup = componentDef(compName = 'Security Groups', compDelete = True )``**  
  **``self.Volume = componentDef(compName = 'Volumes', compDelete = True )``**  
  **``self.KeyPairs = componentDef(compName = 'Key Pairs', compDelete = True )``**  
  **``self.User = componentDef(compName = 'User', compDelete = True, itemsKeep=() )``**  
  **``self.Group = componentDef(compName = 'Group', compDelete = True, itemsKeep=() )``**  
  **``...``**
  
  
  Fields:  
  - **compName**: formatted AWS component Name; no need to change.
  - **compDelete**: boolean flag to block entire AWS component from being deleted (case sensitive!): 
    - **True** to allow AWS component deletion
    - **False** to block AWS component deletion
  - **itemsKeep**: in cases where AWS components don't have tags (key pairs, users, policies, etc), itemsKeep is a list of item names in quotes not to delete - for example itemsKeep=('Seattle', 'Redmond')
  
  Examples: 
  - To prevent all Key Pairs from being deleted, change KeyPair's compDelete from True to False (case sensitive!):  
    ``self.KeyPairs = componentDef(compName = 'Key Pairs', ``**``compDelete = False``**``)``
  - To prevent user Smith from being deleted, set itemsKeep to the following:  
    ``self.Users = componentDef(compName = 'User', compDelete = False, ``**``itemsKeep = ('smith')``**``)``
  - To prevent users Smith and Jones from being deleted, change itemsKeep to the following:  
    ``self.Users = componentDef(compName = 'User', compDelete = False, ``**``itemsKeep = ('smith','jones')``**``)``

