# aws_cleanup.py
**Current AWS components in-scope for aws_cleanup.py:**
- EC2 instances 
- Security Groups 
- Volumes 
- Key Pairs 
- S3 Buckets 
- VPC 
- Subnets 
- Internet Gateways 
- Route Tables

## Running aws_cleanup.py
Both aws_cleanup.py AND aws_cleanup_ext.py files need to be in the same directory
- **INVENTORY OF AWS COMPONENTS (_no deletion_):**
  - **``# python3 aws_cleanup.py``**  
    Run without parameters, aws_cleanup.py displays an inventory of AWS components for all regions. The column "keep(Tag)" shows which AWS items have the tag key "keep". When "aws_cleanup.py --del" is run, items with “keep” tag key are not deleted.

  - **#``python3 aws_cleanup.py --tag <tag_keys>``**  
    Same output as the AWS inventory with the additional column “Search Tag". "Search Tag” shows which _<tag_keys>_ were found in which AWS item. One or more case-insensitive tag keys can be included in the “--tag” parameter (ex: ``python3 aws_cleanup.py --tag ``**``sec545 seattle redmond``**).  
 
 
- **DELETING AWS COMPONENTS:**
  - **``# python3 aws_cleanup.py --del``**  
    Deletes all AWS components except for items with the "keep" tag. The script will first show an inventory of which AWS items will be terminated/deleted, followed by a confirmation prompt.
  - **``# python3 aws_cleanup.py --del --tag <tag_keys>``**   
    Deletes only AWS items having tag keys of _<tag_keys>_. Any AWS item with "keep" tag key will be excluded from removal. Script first displays an inventory of which AWS items will be removed, followed by a confirmation prompt. Having no tags, Key Pairs are out of scope.  


## Advanced Settings:
**The file aws_cleanup_ext.py contains script control settings that can be modified by the end-user.**
- **``constantKeepTag = ['keep']``**  
  Python list of tag keys that flag AWS items from being deleted.  Can have multiple case-insensitive entries.  
  Ex: to replace 'keep' with 'no_delete' and include tag key 'wfw' for blocking, change constantKeepTag to the following:  
    ``constantKeepTag =['no_delete', 'wfw']``
    
- **``self.EC2 = componentDef(compName = 'EC2 instances', compDelete = True)``**  
  **``self.SecGroup = componentDef(compName = 'Security Groups', compDelete = True)``**  
  **``self.Volume = componentDef(compName = 'Volumes', compDelete = True)``**  
  **``self.KeyPairs = componentDef(compName = 'Key Pairs', compDelete = True)...``**  
  
  List of AWS components that aws_cleanup.py script can inventory/delete, along with the flag compDelete that blocks components from being deleted.  
  Ex: To prevent all Key Pairs from being deleted, change KeyPair's compDelete from True to False (case sensitive!):  
    ``self.KeyPairs = componentDef(compName = 'Key Pairs', ``**``compDelete = False)``**
