#!/usr/bin/env python3
#  aws_cleanup.py 
#  2018.06.12 - Created - William Waye 
#  2018.06.24 - wfw - consolidated code via ternary operators & added AWS Volume
#  2018.06.29 - wfw - improved UI, added S3 bucket, removed blacklist (using "keep" tag instead).
#  2018.07.01 - wfw - added POC code for warning about EC2 instances with dependency on
#                     Security Groups targeted for delete.
import sys
import re
try:
  import boto3
except ImportError as e:
  print('This script require Boto3 to be installed and configured.')
  exit()
import argparse
import io
import textwrap
from collections import deque
from botocore.exceptions import ClientError
from collections import defaultdict    # used for initializing nested dictionaries

def formatDispName(*parNames):
  retName = ''
  for parName in parNames:
    if parName:
      if not retName:
        retName = ' ("{}"'.format(parName)
      else:
        retName += ', "{}'.format(parName)
  if retName:
    retName += ')'
  return retName


# Using prefix on the region name to highlight when the region changes.
class regionBreakClass:
  def __init__(self):
    self.breakDisp = ">> "
    self.postDisp = " " * len(self.breakDisp)

  def disp(self, regionName):
    returnVal = self.breakDisp + regionName
    self.breakDisp = self.postDisp
    return returnVal
  
  
class scriptArgs:
  def __init__(self, choice, targetTag = None, keepTag = "keep"):
    self.del_tag = self.del_all = self.inv = False
    if choice == "inv":
      self.inv = True
    elif choice == "del_all":
      self.del_all = True
    elif choice == "del_tag":
      self.del_tag = True
    else:
      raise ValueError('scriptArgs', 'Invalid value passed to scriptArgs')
    self.targetTag = targetTag
    if self.targetTag:
      #  Cleanup any empty strings in target tag list
      tagEx = re.compile('^\s*$')
      self.targetTag = [tag for tag in self.targetTag if not tagEx.match(tag)]
    self.keepTag = keepTag

class awsRpt:
  def __init__(self, *header):
    self.outputRpt = ""
    self.headerList = list(header)
    self.lines = "+"
    self.header = "|"
    self.rows=0
    #  Remove column headers with the value of "None".
    while None in self.headerList:
      self.headerList.remove(None)
    for col in self.headerList:
      if len(col) == 1:
        col.append(len(col[0]))
      if not col[1]:
        #  Default the column width to the size of the column heading
        col[1] = len(col[0])
      if len(col) == 2:
        #  Assume left justification
        col.append("<")
      if type(col[0]) != type(str()) or type(col[1]) != type(int()):
        print(col[0], col[1])
        print('ERROR - Invalid column header list parameter for awsRpt')
        print('FORMAT: awsRpt([["Title1",#],["Title2",#],["Title3,#"],...,["TitleN,#"]])')
        print(' WHERE: TitleN is the column header, and # is the width of the column')
        raise ValueError('awsRpt', 'Invalid column header list')
      col[1] = max(len(col[0]), col[1])
      self.header += '{0:^{fill}}'.format(col[0],fill=col[1]) + "|"
      self.lines += '-' * col[1] + "+"

  def addLine(self, *rptRow):
    rptRowList = list(rptRow)
    #  Do a quick check to make sure that the number of row columns matches the number of 
    #  header columns. Need to loop through as some column values can be None, which
    #  is a skipped column.
    while None in rptRowList:
      rptRowList.remove(None)
    if (len(rptRowList) != len(self.headerList)):
       print ("ERROR - invalid column list for awsRpt.addLine()")
       print ("        The number of elements in the awsRpt.addLine column list (" + str(len(rptRowList))  + ") has to match")
       print ("        number of elements defined in column header (" + str(len(self.headerList)) + ")")
       raise ValueError('awsRpt.addLine', 'Incorrect number of elements in list parameter - has ' + str(len(rptRowList)) + " elements instead of " + str(len(self.headerList)))
    formColumn = []
    for colNo, colData in enumerate(rptRowList):
      formColumn.append(deque(textwrap.wrap(colData, width=self.headerList[colNo][1], subsequent_indent='   ')))
    anyData = True
    bldLine = "|"
    while anyData:
      anyData = False
      bldLine = "|"
      for colNo, colData in enumerate(formColumn):
        try:
          chk=colData.popleft()
          anyData = True
          bldLine += '{0:{just}{fill}}'.format(chk,just=self.headerList[colNo][2],fill=self.headerList[colNo][1]) + "|"
        except:
          bldLine += " " * self.headerList[colNo][1] + "|"
          pass
      if anyData:
        if self.outputRpt:
          self.outputRpt += "\n" + bldLine
          self.rows += 1
        else:
          self.outputRpt = bldLine
          self.rows += 1

  def result(self):
    return self.lines + "\n" +  self.header + "\n" + self.lines + "\n" + self.outputRpt + "\n" + self.lines

class tagScan:
  #  tagScan contains AWS item object's derived attributes (at least as much as could be
  #  derived).
  def __init__(self, tagList, scriptArg):
    self.nameTag = ""
    self.delThisItem = False
    if scriptArg.targetTag is None:
      self.targetTagFound = None
    else:
      self.targetTagFound = ""
    self.keepTagFound = ""
    for t in tagList:
      if t['Key'] == 'Name':
        self.nameTag = t['Value']
      elif scriptArg.keepTag and re.search('^'+re.escape(scriptArg.keepTag)+'$', t['Key'], re.IGNORECASE):
        self.keepTagFound = "Yes"
      elif scriptArg.targetTag is not None:
        for searchTag in scriptArg.targetTag:
          if re.search('^'+re.escape(searchTag)+'$', t['Key'], re.IGNORECASE):
            if self.targetTagFound:
              self.targetTagFound += ", " + searchTag
            else:
              self.targetTagFound = searchTag
    if not self.keepTagFound:
      if scriptArg.del_all:
        self.delThisItem = True
      elif scriptArg.del_tag and self.targetTagFound:
        self.delThisItem = True
        
argUsage = "usage: aws_cleanup.py -[h][--del][--tag <tag_key1> [<tag_key2> [tag_key# ..]]]"
parser = argparse.ArgumentParser(allow_abbrev=False,usage=argUsage)
#  As "del" is a reserved word in Python, needed to have an alnternate destination.
parser.add_argument('-d', '--del', dest='delete', help='delete/terminate AWS components', action="store_true", default=False)
parser.add_argument('-t', '--tag', nargs='+', help='search for components with a specific key value')
args = parser.parse_args()
if args.delete:
  if args.tag:
    aws_cleanupArg = scriptArgs(choice='del_tag', targetTag=args.tag)
  else:
    aws_cleanupArg = scriptArgs(choice='del_all')
else:
  aws_cleanupArg = scriptArgs(choice='inv', targetTag=args.tag)
#exit()
if aws_cleanupArg.targetTag is not None and len(aws_cleanupArg.targetTag) == 0:
  print(argUsage)
  print("aws_cleanup.py: error: argument --tag: expected at least one argument")
  exit(5)

# Make sure the "keep" tag isn't in the targetTag list.
if aws_cleanupArg.targetTag is not None and aws_cleanupArg.keepTag in aws_cleanupArg.targetTag:
  print('\nERROR: --tag cannot include the value "{0}".\nThe tag key "{0}" is used to identify which  AWS items can\'t be terminated or deleted'.format(aws_cleanupArg.keepTag))
  exit(6)
if aws_cleanupArg.targetTag:
  targetTagHeader = ["Search Tag",18,"<"]
  targetTagTitleInfo = ' (search tag "{}")'.format('", "'.join(aws_cleanupArg.targetTag))
else:
  targetTagHeader = None
  targetTagTitleInfo = ''

keepTagHeader = [aws_cleanupArg.keepTag+"(Tag)","","^"]

# Initialize the list of things to terminate
termList=defaultdict(lambda : defaultdict(dict))
# Load in all current regions from AWS
regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]
#regions=['us-west-2','us-east-1','us-east-2']  #for testing#


#  targetTag is the regex pattern used to identify what needs to be listed in the inventory
#  and possibly terminated. targetTag is used in searching the AWS component
#  tag (complete value) OR as a substring in the component's name
print("\n")
print('Inventory of ALL AWS components\n')
output=""
securityGroupDepend=defaultdict(lambda : defaultdict(dict))
keepEC2=defaultdict(lambda : defaultdict(dict))
for currentRegion in sorted(regions):
  print ('Inventorying region {}...'.format(currentRegion))

  #################################################################
  #  EC2 Instances
  #################################################################
  if 'ec2Rpt' not in globals():
    ec2Rpt = awsRpt(*[["Region", 19],["Instance ID", 25],["Name(Tag)", 30],keepTagHeader, targetTagHeader,["Image ID", 30],["Status", 13]])
  client = boto3.client('ec2',region_name=currentRegion)
  regionBreak = regionBreakClass()
  response = client.describe_instances()
  for resp in response['Reservations']:
    for inst in resp['Instances']:
      tagData = tagScan(inst['Tags'] if 'Tags' in inst else [], aws_cleanupArg)
      if aws_cleanupArg.inv:
        ec2Rpt.addLine(regionBreak.disp(currentRegion), inst['InstanceId'],tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,inst['ImageId'],inst['State']['Name'])
      elif inst['State']['Name'] != 'terminated':
        if tagData.delThisItem:
          ec2Rpt.addLine(regionBreak.disp(currentRegion), inst['InstanceId'],tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,inst['ImageId'],inst['State']['Name'])
          termList['EC2'][currentRegion][inst['InstanceId']] = {'DISPLAY_ID': inst['InstanceId'] + formatDispName(tagData.nameTag),'TERMINATED':False}
        elif aws_cleanupArg.del_tag:
          for secGroup in inst['SecurityGroups']:
            if secGroup['GroupId'] not in keepEC2[currentRegion]:
              keepEC2[currentRegion][secGroup['GroupId']]= {'DEPENDENCY':False,'LIST':[]}
            keepEC2[currentRegion][secGroup['GroupId']]['LIST'].append(inst['InstanceId'])

  #################################################################
  #  Security Group
  #################################################################
  if 'secGroupRpt' not in globals():
    secGroupRpt = awsRpt(*[["Region", 19],["Group ID", 25],["Name(Tag)", 30],keepTagHeader,targetTagHeader,["Group Name", 30],["Description", 35]])
  regionBreak = regionBreakClass()
  response = client.describe_security_groups()
  for resp in response['SecurityGroups']:
    # ... can't do anything with the default security group
    if resp['GroupName'] != 'default':
      tagData = tagScan(resp['Tags'] if 'Tags' in resp else [], aws_cleanupArg)
      secGroupRptCommonLine = (regionBreak.disp(currentRegion), resp['GroupId'],tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,resp['GroupName'],resp['Description'])
      if aws_cleanupArg.inv:
        secGroupRpt.addLine(*secGroupRptCommonLine)
      elif tagData.delThisItem:
        secGroupRpt.addLine(*secGroupRptCommonLine)
        termList['SECGROUP'][currentRegion][resp['GroupId']] = {'DISPLAY_ID': resp['GroupId'] + formatDispName(tagData.nameTag, resp['GroupName'], resp['Description'])}
        if aws_cleanupArg.del_tag and resp['GroupId'] in keepEC2[currentRegion]:
          keepEC2[currentRegion][resp['GroupId']]['DEPENDENCY'] = True
          

  #################################################################
  #  Volumes
  #################################################################
  if 'volRpt' not in globals():
    volRpt = awsRpt(*[["Region", 19],["Volume ID", 25],["Name(Tag)", 30],keepTagHeader,targetTagHeader,["Vol Type", 10],["State", 15]])
  regionBreak = regionBreakClass()
  volumes = client.describe_volumes()
  for vol in volumes['Volumes']:
    tagData = tagScan(vol['Tags'] if 'Tags' in vol else [], aws_cleanupArg)
    volRptCommonLine = (regionBreak.disp(currentRegion), vol['VolumeId'],tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,vol['VolumeType'],vol['State'])
    if aws_cleanupArg.inv:
      volRpt.addLine(*volRptCommonLine)
    elif tagData.delThisItem:
      volRpt.addLine(*volRptCommonLine)
      termList['VOLUME'][currentRegion][vol['VolumeId']] = {'DISPLAY_ID': vol['VolumeId'] + formatDispName(tagData.nameTag)}

  #################################################################
  #  Key Pairs
  #################################################################
  if 'secKeyPairsRpt' not in globals():
    secKeyPairsRpt = awsRpt(*[["Region", 19],["KeyName", 30]])
  # Skipping key pairs if deleting by tags (as they have no tags)
  if not aws_cleanupArg.del_tag:
    regionBreak = regionBreakClass()
    response = client.describe_key_pairs()
    for resp in response['KeyPairs']:
      if aws_cleanupArg.inv:
        secKeyPairsRpt.addLine(regionBreak.disp(currentRegion), resp['KeyName'])
      else:
        secKeyPairsRpt.addLine(regionBreak.disp(currentRegion), resp['KeyName'])
        if not termList['KeyPairs'][currentRegion]:
          termList['KeyPairs'][currentRegion] = [resp['KeyName']]
        else:
          termList['KeyPairs'][currentRegion].append(resp['KeyName'])

if ec2Rpt.rows > 0:
  output += '\nEC2 Instances{}:\n'.format(targetTagTitleInfo)
  output += ec2Rpt.result() + "\n"
if secGroupRpt.rows > 0:
  output += '\nSecurity Groups{}:\n'.format(targetTagTitleInfo)
  output += secGroupRpt.result() + "\n"
if volRpt.rows > 0:
  output += '\nVolumes{}:\n'.format(targetTagTitleInfo)
  output += volRpt.result() + "\n"
if secKeyPairsRpt.rows > 0:
  output += '\nKey Pairs:\n'
  output += secKeyPairsRpt.result() + "\n"
elif aws_cleanupArg.del_tag:
  output += '\nKey Pairs: not included for tag delete, as key pairs don''t have tags\n'


#################################################################
#  S3 Buckets
#################################################################
clientS3 = boto3.client('s3')
s3Rpt = awsRpt(*[["Bucket Name", 40],keepTagHeader,targetTagHeader])
for buckets in clientS3.list_buckets()['Buckets']:
  try:
    bucketTag = clientS3.get_bucket_tagging(Bucket=buckets['Name'])['TagSet']
  except ClientError as e:
    bucketTag=[]
  tagData = tagScan(bucketTag, aws_cleanupArg)
  if aws_cleanupArg.inv:
    s3Rpt.addLine(buckets['Name'], tagData.keepTagFound, tagData.targetTagFound)
  elif tagData.delThisItem:
    s3Rpt.addLine(buckets['Name'], tagData.keepTagFound, tagData.targetTagFound)
    if not termList['S3']:
      # Initialize termList['S3'] bucket list
      termList['S3'] = [buckets['Name']]
    else:
      termList['S3'].append(buckets['Name'])
if s3Rpt.rows > 0:
  output += '\nS3 Buckets{}:\n'.format(targetTagTitleInfo)
  output += s3Rpt.result()



print(output)
print("\n")
if not aws_cleanupArg.inv:
  if not termList:
    print("No AWS items were found that were in-scope for terminating/deleting")
    if aws_cleanupArg.del_tag:
      print('Search tag: "{}"'.format('", "'.join(aws_cleanupArg.targetTag)))
  else:
    #  Verify that they really want to terminate/delete everything listed as in-scope.
    if aws_cleanupArg.del_all:
      print("Terminating/deleting ALL components")
    else:
      print('Deleting items with the tag(s): "' + '", "'.join(aws_cleanupArg.targetTag) + '"')
      keepEC2Output = ""
      if keepEC2:
        for keepRegion, keepGroupItems in keepEC2.items():
          for keepGroupId, keepGroupInfo in keepGroupItems.items():
            if keepGroupInfo['DEPENDENCY']:
              keepEC2Output = "  Region:" + keepRegion + ", Security Group: " + keepGroupId + ", Dependant EC2 Instances: " + ", ".join(keepGroupInfo['LIST'])
      if keepEC2Output:
        print('WARNING - the following Security Groups identified to delete have EC2 dependant instances NOT being deleted.')
        print('          If you proceed, there will be a failure message for these Security Groups:')
        print(keepEC2Output + "\n")  
    verifyTermProceed = input('Type "yes" to terminate/delete above listed AWS components: ')
    #################################################################
    #  EC2 Instances terminate
    #################################################################
    if verifyTermProceed == "yes":
      if 'EC2' in termList:
        for currentRegion,idDict in termList['EC2'].items():
          ec2 = boto3.resource('ec2',region_name=currentRegion)

          for id, idDetail in idDict.items():
            print('Terminating ' + currentRegion + ' EC2 instance ' + idDetail['DISPLAY_ID'])
            ec2DryRunSuccessful=False
            #  Not sure if there's an advantage to having the DryRun test;
            #  will leave this segment of code in place for future.
            try:
              response = ec2.Instance(id).terminate(DryRun=True)
              #  Should never reach this point, but just in case...
              ec2DryRunSuccess = True
            except ClientError as e:
              if e.response["Error"]["Code"] == "DryRunOperation":
                ec2DryRunSuccess = True
              else:
                print(e, '\n')
                ec2DryRunSuccess = False
            if ec2DryRunSuccess:
              try:
                response = ec2.Instance(id).terminate( DryRun=False)
                idDetail['TERMINATED'] = True
              except ClientError as e:
                print("   ", e, '\n')
        #  Loop through terminated instances and wait for the termination to 
        #  complete before continuing.
        for currentRegion,idDict in termList['EC2'].items():
          ec2 = boto3.resource('ec2',region_name=currentRegion)
          for id, idDetail in idDict.items():
            if idDetail['TERMINATED']:
              instance = ec2.Instance(id);
              print('Waiting for ' + currentRegion + ' EC2 instance ' + idDetail['DISPLAY_ID'] + ' to terminate...');
              instance.wait_until_terminated()

      #################################################################
      #  Security Groups delete
      #################################################################
      if 'SECGROUP' in termList:
        #  Delete Security Groups
        for currentRegion,idDict in termList['SECGROUP'].items():
          ec2 = boto3.resource('ec2',region_name=currentRegion)
          for id, idDetail in idDict.items():
            print('Deleting ' + currentRegion + ' Security Group ' + idDetail['DISPLAY_ID'])
            try:
              response = ec2.SecurityGroup(id).delete(DryRun=False)
            except ClientError as e:
              print("   ", e, '\n')
 
      #################################################################
      #  Volumes delete
      #################################################################
      if 'VOLUME' in termList:
        #  Delete Security Groups
        print("NOTE: Volumes may already been deleted with assoicated EC2 instances.")
        for currentRegion,idDict in termList['VOLUME'].items():
          ec2 = boto3.resource('ec2',region_name=currentRegion)
          for id, idDetail in idDict.items():
            print('Deleting ' + currentRegion + ' Volume ' + idDetail['DISPLAY_ID'])
            try:
              response = ec2.Volume(id).delete(DryRun=False)
            except ClientError as e:
              if e.response["Error"]["Code"] == 'InvalidVolume.NotFound':
                print("    Volume already deleted")
              else:
                print("   ", e, '\n')


      #################################################################
      #  Key Pairs delete
      #################################################################
      if 'KeyPairs' in termList:
        for currentRegion,idDict in termList['KeyPairs'].items():
          ec2 = boto3.resource('ec2',region_name=currentRegion)
          for colData in idDict:
            print('Deleting Key Pair "' + colData + '"')
            try:
              response = ec2.KeyPair(colData).delete(DryRun=False)
            except ClientError as e:
              print("   ", e, '\n')
 

      #################################################################
      #  S3 buckets delete
      #################################################################
      if 'S3' in termList:
        s3 = boto3.resource('s3')
        for bucketName in termList['S3']:
          #  Before a bucket can be deleted, the objects in the bucket first have to be
          #  deleted.
          print('Deleting any objects contained in S3 Bucket ' + bucketName + '...')
          try:
            ign = s3.Bucket(bucketName).objects.delete()
          except ClientError as e:
            print("   ", e, '\n')
          print('Deleting S3 Bucket ' + bucketName)
          try:
            ign = s3.Bucket(bucketName).delete()
          except ClientError as e:
            print("   ", e, '\n')
        
    else:
      print('Exiting script WITHOUT terminating/deleting AWS components')
