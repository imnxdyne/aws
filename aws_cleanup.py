#!/usr/bin/env python3
#  aws_cleanup.py 
#  2018.06.12 - Created - William Waye 
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
import os.path
from collections import deque
from botocore.exceptions import ClientError
delPattern="sec545";

#  blacklist.csv file expected to be found in the same directory as the aws_cleanup.py script.
blackListFile=os.path.join(sys.path[0], 'blacklist.csv')
#blackListFile='blacklist.csv'

# blackList format:
#  blackList={"<ID1>":"<region>"[, "<ID2>":"<region>"[, "<IDn>":"<region...]]}
#     WHERE: <IDn> is the unique identifier (Instance ID for EC2 instances, Group ID for Security Groups, 
#                 Key Name for Key Pairs,...)
#            <region>: region name (ex: "us-west-2", "us-east-1",...) or wild-card "*".
#blackList={"sg-0b1325235sst435235":"us-west-2","i-0d2d0e7q42342352525":"*","MyEC2":"*"}
blackList={}

class scriptArgs:
  def __init__(self, parChoice):
    self.delId = self.delAll = self.inv = False
    if parChoice == "inv":
      self.inv = True
    elif parChoice == "del_all":
      self.delAll = True
    elif parChoice == "del_id":
      self.delId = True
    else:
      raise ValueError('scriptArgs', 'Invalid value passed to scriptArgs')
    
class awsRpt:
  def __init__(self, *header):
    self.outputRpt = ""
    self.headerList = list(header)
    self.lines = "+"
    self.header = "|"
    self.rows=0
    for col in self.headerList:
      if len(col) == 1:
        col.append(len(col[0]))
      if not col[1]:
        col[1] = len(col[0])
      if len(col) == 2:
        col.append("<")
      if type(col[0]) != type(str()) or type(col[1]) != type(int()):
        print('ERROR - Invalid column header list parameter for awsRpt')
        print('FORMAT: awsRpt([["Title1",#],["Title2",#],["Title3,#"],...,["TitleN,#"]])')
        print(' WHERE: TitleN is the column header, and # is the width of the column')
        raise ValueError('awsRpt', 'Invalid column header list')
      col[1] = max(len(col[0]), col[1])
      self.header += '{0:^{fill}}'.format(col[0],fill=col[1]) + "|"
      self.lines += '-' * col[1] + "+"

  def addLine(self, *rptLine):
    if (len(rptLine) != len(self.headerList)):
       print ("ERROR - invalid column list for awsRpt.addLine()")
       print ("        The number of elements in the awsRpt.addLine column list (" + str(len(rptLine))  + ") has to match")
       print ("        number of elements defined in column header (" + str(len(self.headerList)) + ")")
       raise ValueError('awsRpt.addLine', 'Incorrect number of elements in list parameter - has ' + str(len(rptLine)) + " elements instead of " + str(len(self.headerList)))
    formColumn = []
    for colNo, colData in enumerate(rptLine):
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
  #  tagScan contains tagScan's object's derived attributes (at least as much as could be
  #  derived).
  def __init__(self, tagList, chkBlackListId, chkBlackListRegion, scriptArg, nameAlt = ""):
    self.nameTag = ""
    self.patternTag = False
    self.nameTagInscope = False
    self.nameAltInscope = False
    self.onBlackList = False
    self.delScope = ""
    self.delThisComponent = False
    for t in tagList:
      if t['Key'] == 'Name':
        self.nameTag = t['Value']
        if re.search(delPattern, t['Value'],re.IGNORECASE):
          self.nameTagInscope = True
      elif re.search('^'+delPattern+'$', t['Key'], re.IGNORECASE):
        self.patternTag = True
    if nameAlt:
      if re.search(delPattern, nameAlt, re.IGNORECASE):
        self.nameAltInscope = True
      
    if chkBlackListId in blackList and (blackList[chkBlackListId] == "*" or blackList[chkBlackListId] == currentRegion):
      self.onBlackList = True
      self.delScope="blacklist"
    elif self.patternTag or self.nameTagInscope or self.nameAltInscope:
      self.delScope="all & ID"
    else:
      self.delScope="all"
    #  As the logic behind determining what should and shouldn't be deleted is common for AWS components,
    #  centralized the login here.
    if not self.onBlackList and (scriptArg.delAll or (scriptArg.delId and (self.patternTag or self.nameTagInscope or self.nameAltInscope))):
      self.delThisComponent = True

parser = argparse.ArgumentParser(allow_abbrev=False,usage="aws_cleanup.py -[h][--inv | --del_id | --del_all]")
parser.add_argument('--del_id', help='drop AWS components identified with "' + delPattern + '"', action="store_true", default=False)
parser.add_argument('--del_all', help='drop ALL AWS components.', action="store_true", default=False)
args = parser.parse_args()
if args.del_id and args.del_all:
  raise argparse.ArgumentTypeError('cannot have arguments "--del_id" and "--del_all" at the same time')
if args.del_id:
  aws_cleanupArg = scriptArgs('del_id')
elif args.del_all:
  aws_cleanupArg = scriptArgs('del_all')
else:
  aws_cleanupArg = scriptArgs('inv')

termList={}
# Load in all current regions from AWS
regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]
# regions=['us-west-2','us-east-1','us-east-2']  #for testing#

#  Read in file containing component's blacklisted from dropping:
if os.path.exists(blackListFile):
  errBlackList = False
  print("Reading in AWS components contained in file " + blackListFile)
  with open(blackListFile, 'r') as fileBl:
    for rowBl in fileBl:
      rowBl = re.sub('\n$', '', rowBl)
      if not re.search('^\s*#', rowBl) and not re.search('^\s*$', rowBl):
        colBl = rowBl.split(",",maxsplit=1)
        if len(colBl) == 1:
          print('  Invalid line format in blacklist.csv, row "' + rowBl + '"')
          errBlackList = True
        else:
          if colBl[0] == "*" or colBl[0] in regions:
            blackList[colBl[1]] = colBl[0]
          else:
            print('  Invalid region in blacklist.csv, row "' + rowBl + '"')
            errBlackList = True
  if errBlackList:
    sys.exit("ERROR: format issue with blacklist file " + blackListFile + ", terminating script.")
else:
  print("Blacklist file " + blackListFile + " not found.")

#  delPattern is the regex pattern used to identify what needs to be listed in the inventory
#  and possibly terminated. delPattern is used in searching the AWS component
#  tag (complete value) OR as a substring in the component's name
print("\n")
if aws_cleanupArg.delAll or aws_cleanupArg.inv:
  print('Inventory of ALL AWS components\n')
else:
  print ('Inventory of AWS components either tagged as "' + delPattern + '" or the name contains "' + delPattern + '":\n')
output=""
for currentRegion in regions:
  print ('Inventorying region ' + currentRegion + '...') 
  if aws_cleanupArg.inv:
    ec2Rpt = awsRpt(["Instance ID", 25],["Name(Tag)", 40],[delPattern+"(Tag)","","^"],["Image ID", 30],["Status", 20],["Delete Scope", 11])
  else:
    ec2Rpt = awsRpt(["Instance ID", 25],["Name(Tag)", 40],[delPattern+"(Tag)","","^"],["Image ID", 30],["Status", 20])
  client = boto3.client('ec2',region_name=currentRegion)
  ec2 = boto3.resource('ec2',region_name=currentRegion)
  response = client.describe_instances()
  for resp in response['Reservations']:
    for inst in resp['Instances']:
      #  Read through the Tags list
      if 'Tags' in inst:
        tagData = tagScan(inst['Tags'], inst['InstanceId'], currentRegion, aws_cleanupArg)
      else:
        tagData = tagScan([],inst['InstanceId'], currentRegion, aws_cleanupArg)
      
      if aws_cleanupArg.inv:
        ec2Rpt.addLine(inst['InstanceId'],tagData.nameTag,'{}'.format("Yes" if tagData.patternTag else ""),inst['ImageId'],inst['State']['Name'],'{}'.format("N/A" if inst['State']['Name'] == 'terminated' else tagData.delScope))
      else:
        if inst['State']['Name'] != 'terminated' and tagData.delThisComponent:
          ec2Rpt.addLine(inst['InstanceId'],tagData.nameTag,'{}'.format("Yes" if tagData.patternTag else ""),inst['ImageId'],inst['State']['Name'])
          #  Setup nested dictionary
          if not 'EC2' in termList:
            termList['EC2'] = {}
          if not currentRegion in termList['EC2']:
            termList['EC2'][currentRegion] = {}
          if tagData.nameTag:
            termList['EC2'][currentRegion][inst['InstanceId']] = {'DISPLAY_ID': inst['InstanceId'] + ' (' + tagData.nameTag + ')','TERMINATED':False}
          else:
            termList['EC2'][currentRegion][inst['InstanceId']] = {'DISPLAY_ID': inst['InstanceId'],'TERMINATED':False}
  if ec2Rpt.rows > 0:
    output += '\nEC2 Instances for region ' + currentRegion + ':\n'
    output += ec2Rpt.result() + "\n"
  
  if aws_cleanupArg.inv:
    secGroupRpt = awsRpt(["Group ID", 25],["Name(Tag)", 30],[delPattern+"(Tag)","","^"],["Group Name", 30],["Description", 45],["Delete Scope", 11])
  else:
    secGroupRpt = awsRpt(["Group ID", 25],["Name(Tag)", 30],[delPattern+"(Tag)","","^"],["Group Name", 30],["Description", 45])

  response = client.describe_security_groups()
  for resp in response['SecurityGroups']:
    # ... can't do anything with the default security group
    if resp['GroupName'] != 'default':
      #  The security group may not have a Tag list:
      if 'Tags' in resp:
        tagData = tagScan(resp['Tags'], resp['GroupId'], currentRegion, aws_cleanupArg, resp['GroupName'])
      else:
        tagData = tagScan([], resp['GroupId'], currentRegion, aws_cleanupArg,resp['GroupName'])
      if aws_cleanupArg.inv:
        secGroupRpt.addLine(resp['GroupId'],tagData.nameTag,'{}'.format("Yes" if tagData.patternTag else ""),resp['GroupName'],resp['Description'],tagData.delScope)
      else:
        if tagData.delThisComponent:
          secGroupRpt.addLine(resp['GroupId'],tagData.nameTag,'{}'.format("Yes" if tagData.patternTag else ""),resp['GroupName'],resp['Description'])
          if not 'SECGROUP' in termList:
            termList['SECGROUP'] = {}
          if not currentRegion in termList['SECGROUP']:
            termList['SECGROUP'][currentRegion] = {}
          if tagData.nameTag:
            termList['SECGROUP'][currentRegion][resp['GroupId']] = {'DISPLAY_ID': resp['GroupId'] + ' ("' + resp['GroupName'] + '", "' + tagData.nameTag + '")'}
          else:
            termList['SECGROUP'][currentRegion][resp['GroupId']] = {'DISPLAY_ID': resp['GroupId'] + ' ("' + resp['GroupName'] + '")'}

  if secGroupRpt.rows > 0:
    output += '\nSecurity Groups for region ' + currentRegion + ':\n'
    output += secGroupRpt.result() + "\n"


  if aws_cleanupArg.inv:
    secKeyPairsRpt = awsRpt(["KeyName", 30],["Delete Scope", 11])
  else:
    secKeyPairsRpt = awsRpt(["KeyName", 30])

  response = client.describe_key_pairs()
  for resp in response['KeyPairs']:
    tagData = tagScan([], resp['KeyName'], currentRegion, aws_cleanupArg, resp['KeyName'])
    if aws_cleanupArg.inv:
      secKeyPairsRpt.addLine(resp['KeyName'],tagData.delScope)
    else:
      if tagData.delThisComponent:
        secKeyPairsRpt.addLine(resp['KeyName'])
        if not 'KeyPairs' in termList:
          termList['KeyPairs'] = {}
        if not currentRegion in termList['KeyPairs']:
          termList['KeyPairs'][currentRegion] = []
        termList['KeyPairs'][currentRegion].append(resp['KeyName'])
  if secKeyPairsRpt.rows > 0:
    output += '\nKey Pairs for region ' + currentRegion + ':\n'
    output += secKeyPairsRpt.result() + "\n"

print(output)
print("\n")
if not aws_cleanupArg.inv and termList:
  #  Verify that they really want to drop everything listed as in-scope.
  if not blackList:
    print('NOTE: no blacklist file utilized (if you want to block some of the above components from being removed.)')
  verifyTermProceed = input('Type "yes" to terminate/drop above AWS components: ')
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
      #  Loop through the terminated instances and wait for the termination to complete.
      for currentRegion,idDict in termList['EC2'].items():
        ec2 = boto3.resource('ec2',region_name=currentRegion)
        for id, idDetail in idDict.items():
          if idDetail['TERMINATED']:
            instance = ec2.Instance(id);
            print('Waiting for ' + currentRegion + ' EC2 instance ' + idDetail['DISPLAY_ID'] + ' to terminate...');
            instance.wait_until_terminated()
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
    if 'KeyPairs' in termList:
      for currentRegion,idDict in termList['KeyPairs'].items():
        ec2 = boto3.resource('ec2',region_name=currentRegion)
        for colData in idDict:
          print('Dropping Key Pair "' + colData + '"')
          try:
            response = ec2.KeyPair(colData).delete(DryRun=False)
          except ClientError as e:
            print("   ",e, '\n')

  else:
    print('Exiting script WITHOUT terminating/dropping AWS components')
