#!/usr/bin/env python3
#  aws_cleanup.py 
#  2018.06.12 - Created - William Waye 
#  2018.06.24 - ww - consolidated code via ternary operators & added AWS Volume
#  2018.06.29 - ww - improved UI, added S3 bucket, removed blacklist (using "keep" tag instead).
#  2018.07.01 - ww - added POC code for warning about EC2 instances with dependency on
#                     Security Groups targeted for delete.
#  2018.07.09 - ww - added a couple traps for handling (potential) common errors for AWS connections.
#  2018.07.10 - ww - Changed delete verification from entering "yes" to a 4-digit delete
#     verification code, added termTrackClass (primarily for having variable constants instead of
#     string constants for dictionary indexes), and added "--test_region" argument (reduced number of regions
#     during dev testing for improved performance). Changed region break format.
#  2018.07.17 - ww - Added VPC, subnets, internet gateways, route tables. Added a couple
#     dependency warnings.
import sys
import os
import re
import random
try:
  import boto3
except ImportError as e:
  print('This script requires Boto3 to be installed and configured.')
  print('Can install via "pip install boto3"')
  exit()
import argparse
import io
import textwrap
from collections import deque
from botocore.exceptions import ClientError,NoCredentialsError,EndpointConnectionError
from collections import defaultdict,namedtuple    # used for initializing nested dictionaries

def formatDispName(*parNames):
  parNamesDisp = []
  for n in parNames:
    if n:
      parNamesDisp.append(n)
  if parNamesDisp:
    retName = ' ({})'.format(', '.join(parNamesDisp))
  else:
    retName = ''
  return retName


def chkRouteAssociations(parRouteId):
  #  Digging through the route table associations to see if the route table is set as 'Main' 
  #  was repeated in a couple areas - easier to have as a function and include any
  #  associated subnets.
  clientEC2Route = boto3.client('ec2')
  routeTableIsMain = False
  routeTableSubnets = []

  for idChk in clientEC2Route.describe_route_tables(Filters=[{'Name': 'route-table-id', 'Values':[parRouteId]}])['RouteTables']:
    if idChk['Associations']:
      for chkAssociations in idChk['Associations']:
        if 'Main' in chkAssociations and chkAssociations['Main']:
          routeTableIsMain = True
        if 'SubnetId' in chkAssociations:
          routeTableSubnets.append(chkAssociations['SubnetId'])
  return{'Main': routeTableIsMain, 'Subnets': ', '.join(routeTableSubnets)}

componentDef = namedtuple("componentDef", ['compName', 'compDelete'])
class termTrackClass:
  def __init__(self):
    # Initialize the dictionary of items to delete/terminate
    self.x=defaultdict(lambda : defaultdict(dict))
 
    #  The value "compName" is utilized for two things:
    #    1) Unique dictionary index for termTrackClass attribute "x"
    #    2) Title / display name
    #  CompDelete is for future use
    self.EC2 = componentDef(compName = 'EC2 instances', compDelete = True)
    self.SecGroup = componentDef(compName = 'Security Groups', compDelete = True)
    self.Volume = componentDef(compName = 'Volumes', compDelete = True)
    self.KeyPairs = componentDef(compName = 'Key Pairs', compDelete = True)
    self.S3 = componentDef(compName = 'S3 Buckets', compDelete = True)
    self.VPC = componentDef(compName = 'VPC', compDelete = True)
    self.Subnet = componentDef(compName = 'Subnets', compDelete = True)
    self.InternetGateway = componentDef(compName = 'Internet Gateways', compDelete = True)
    self.RouteTable = componentDef(compName = 'Route Tables', compDelete = True)

  
class regionBreakNewClass:
  def __init__(self):
    self.newRpt = True
    self.regionNameTrack = None

  def lineBreak(self, regionName):
    returnVal = False
    if self.regionNameTrack is None:
      self.regionNameTrack = regionName
    else:
      if self.regionNameTrack != regionName:
        returnVal = True
        self.regionNameTrack = regionName
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

  def addLine(self, rptBreak, *rptRow):
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
    if rptBreak:
      self.outputRpt += "\n" + self.lines
      self.rows += 1
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
parser.add_argument('--test_region', help='reduces number of in-scope regions for code testing for better performance -wfw', action="store_true", default=False)
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

# Initialize the dictionary of items to delete/terminate
termTrack = termTrackClass()
print('AWS components in-scope for {}:'.format(sys.argv[0]))
for id, idDetail in vars(termTrack).items():
  if type(idDetail) is componentDef:
    print('  * {}'.format(idDetail.compName))

# Load all regions from AWS into region list.
# As this is where the initial connection occurs to AWS, included a couple traps to handle
# connectivity errors - network MIA, invalid AWS credentials, missing AWS aws credentials,....
try:
  regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]
except NoCredentialsError as e:
  print('ERROR: Cannot connect to AWS - possible credential issue.\nVerify that local AWS credentials in .aws are configured correctly.')
  exit(10)
except EndpointConnectionError as e:
  print('ERROR: Cannot connect to AWS - possible network issue.\nAWS error message: ', e)
  exit(11)
except:
  #  For any other errors...(there may be a real issue with obtaining AWS regions...).
  print("Unexpected error:", sys.exc_info()[0])
  #  If .aws directory doesn't exist, the error handling occurs here at the catch-all (strangely 
  #  enough, not handled in NoCredentialsError). Check to see if the .aws directory even 
  #  exists. If it isn't there, give a warning.
  if not os.path.isdir(os.path.expanduser('~/.aws')):
    print('It looks like the .aws directory for credentials is missing.')
  print('Make sure the local credentials are setup correctly - instructions can be found at https://aws.amazon.com/developers/getting-started/python')
  exit(12)
if args.test_region:
  regions=['us-west-1','us-west-2','us-east-1','us-east-2']  #for testing#
  print('Reduced regions for script testing: ', regions, '\n\n')


#  targetTag is the regex pattern used to identify what needs to be listed in the inventory
#  and possibly terminated. targetTag is used in searching the AWS component
#  tag (complete value) OR as a substring in the component's name
print("\n")
print('Inventory of ALL AWS components\n')
output=""
securityGroupDepend=defaultdict(lambda : defaultdict(dict))
keepEC2=defaultdict(lambda : defaultdict(dict))
regionBreakEC2 = regionBreakNewClass()
regionBreakSecGroup = regionBreakNewClass()
regionBreakVolume = regionBreakNewClass()
regionBreakKeyPairs = regionBreakNewClass()
regionBreakS3 = regionBreakNewClass()

clientEC2 = boto3.client('ec2')
for currentRegion in sorted(regions):
  print ('Inventorying region {}...'.format(currentRegion))
  clientEC2Region = boto3.client('ec2',region_name=currentRegion)


  #################################################################
  #  EC2 Instances
  #################################################################
  if 'ec2Rpt' not in globals():
    ec2Rpt = awsRpt(*[["Region", 16],["Instance ID", 25],["Name(Tag)", 30],keepTagHeader, targetTagHeader,["Image ID", 30],["Status", 13]])
  for resp in clientEC2Region.describe_instances()['Reservations']:
    for inst in resp['Instances']:
      tagData = tagScan(inst['Tags'] if 'Tags' in inst else [], aws_cleanupArg)
      if aws_cleanupArg.inv:
        ec2Rpt.addLine(regionBreakEC2.lineBreak(currentRegion), currentRegion, inst['InstanceId'],tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,inst['ImageId'],inst['State']['Name'])
      elif inst['State']['Name'] != 'terminated':
        if tagData.delThisItem:
          ec2Rpt.addLine(regionBreakEC2.lineBreak(currentRegion), currentRegion, inst['InstanceId'],tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,inst['ImageId'],inst['State']['Name'])
          termTrack.x[termTrack.EC2][currentRegion][inst['InstanceId']] = {'DISPLAY_ID': inst['InstanceId'] + formatDispName(tagData.nameTag),'TERMINATED':False}
        elif aws_cleanupArg.del_tag:
          for secGroup in inst['SecurityGroups']:
            if secGroup['GroupId'] not in keepEC2[currentRegion]:
              keepEC2[currentRegion][secGroup['GroupId']]= {'DEPENDENCY':False,'LIST':[]}
            keepEC2[currentRegion][secGroup['GroupId']]['LIST'].append(inst['InstanceId'])

  #################################################################
  #  Security Group
  #################################################################
  if 'secGroupRpt' not in globals():
    secGroupRpt = awsRpt(*[["Region", 16],["Group ID", 25],["Name(Tag)", 30],keepTagHeader,targetTagHeader,["Group Name", 30],["Description", 35]])
  for resp in clientEC2Region.describe_security_groups()['SecurityGroups']:
    # ... can't do anything with the default security group
    if resp['GroupName'] != 'default':
      tagData = tagScan(resp['Tags'] if 'Tags' in resp else [], aws_cleanupArg)
      secGroupRptCommonLine = (currentRegion, resp['GroupId'],tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,resp['GroupName'],resp['Description'])
      if aws_cleanupArg.inv:
        secGroupRpt.addLine(regionBreakSecGroup.lineBreak(currentRegion), *secGroupRptCommonLine)
      elif tagData.delThisItem:
        secGroupRpt.addLine(regionBreakSecGroup.lineBreak(currentRegion), *secGroupRptCommonLine)
        termTrack.x[termTrack.SecGroup][currentRegion][resp['GroupId']] = {'DISPLAY_ID': resp['GroupId'] + formatDispName(tagData.nameTag, resp['GroupName'], resp['Description'])}
        if aws_cleanupArg.del_tag and resp['GroupId'] in keepEC2[currentRegion]:
          keepEC2[currentRegion][resp['GroupId']]['DEPENDENCY'] = True
          

  #################################################################
  #  Volumes
  #################################################################
  if 'volRpt' not in globals():
    volRpt = awsRpt(*[["Region", 16],["Volume ID", 25],["Name(Tag)", 30],keepTagHeader,targetTagHeader,["Vol Type", 10],["State", 15]])
  for vol in clientEC2Region.describe_volumes()['Volumes']:
    tagData = tagScan(vol['Tags'] if 'Tags' in vol else [], aws_cleanupArg)
    volRptCommonLine = (currentRegion, vol['VolumeId'],tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,vol['VolumeType'],vol['State'])
    if aws_cleanupArg.inv:
      volRpt.addLine(regionBreakVolume.lineBreak(currentRegion), *volRptCommonLine)
    elif tagData.delThisItem:
      volRpt.addLine(regionBreakVolume.lineBreak(currentRegion), *volRptCommonLine)
      termTrack.x[termTrack.Volume][currentRegion][vol['VolumeId']] = {'DISPLAY_ID': vol['VolumeId'] + formatDispName(tagData.nameTag)}

  #################################################################
  #  Key Pairs
  #################################################################
  if 'secKeyPairsRpt' not in globals():
    secKeyPairsRpt = awsRpt(*[["Region", 16],["KeyName", 30]])
  # Skipping key pairs if deleting by tags (as they have no tags)
  if not aws_cleanupArg.del_tag:
    for resp in clientEC2Region.describe_key_pairs()['KeyPairs']:
      if aws_cleanupArg.inv:
        secKeyPairsRpt.addLine(regionBreakKeyPairs.lineBreak(currentRegion), currentRegion, resp['KeyName'])
      else:
        secKeyPairsRpt.addLine(regionBreakKeyPairs.lineBreak(currentRegion), currentRegion, resp['KeyName'])
        if not termTrack.x[termTrack.KeyPairs][currentRegion]:
          termTrack.x[termTrack.KeyPairs][currentRegion] = [resp['KeyName']]
        else:
          termTrack.x[termTrack.KeyPairs][currentRegion].append(resp['KeyName'])

if ec2Rpt.rows > 0:
  output += '\nEC2 Instances{}:\n'.format(targetTagTitleInfo)
  output += ec2Rpt.result() + "\n" * 2
if secGroupRpt.rows > 0:
  output += '\nSecurity Groups{}:\n'.format(targetTagTitleInfo)
  output += secGroupRpt.result() + "\n" * 2
if volRpt.rows > 0:
  output += '\nVolumes{}:\n'.format(targetTagTitleInfo)
  output += volRpt.result() + "\n" * 2
if secKeyPairsRpt.rows > 0:
  output += '\nKey Pairs:\n'
  output += secKeyPairsRpt.result() + "\n" * 2
elif aws_cleanupArg.del_tag:
  output += '\nKey Pairs: not included for tag delete, as key pairs don''t have tags\n'

#################################################################
#  VPC
#################################################################
vpcRpt = awsRpt(*[["CIDR Block", 20],["VPC ID", 25],["Name(Tag)", 30],keepTagHeader,targetTagHeader,["State", 10]])
for vpcs in clientEC2.describe_vpcs()['Vpcs']:
  tagData = tagScan(vpcs['Tags'] if 'Tags' in vpcs else [], aws_cleanupArg)
  vpcsRptCommonLine = (vpcs['CidrBlock'], vpcs['VpcId'], tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,vpcs['State'])
  if aws_cleanupArg.inv:
    vpcRpt.addLine(False, *vpcsRptCommonLine)
  elif tagData.delThisItem:
    vpcRpt.addLine(False, *vpcsRptCommonLine)
    termTrack.x[termTrack.VPC][vpcs['VpcId']] = {'DISPLAY_ID': vpcs['VpcId'] + formatDispName(tagData.nameTag, vpcs['CidrBlock'])}
if vpcRpt.rows > 0:
  output += '\nVPC{}:\n'.format(targetTagTitleInfo)
  output += vpcRpt.result()  + "\n" * 2

#################################################################
#  Route Table
#################################################################
routeTableRpt = awsRpt(*[["Route Table ID", 28],["VPC ID", 25],["Main", 4],["Name(Tag)", 30],keepTagHeader,targetTagHeader])
for routeTables in clientEC2.describe_route_tables()['RouteTables']:
  tagData = tagScan(routeTables['Tags'] if 'Tags' in routeTables else [], aws_cleanupArg)
  routeAssociations = chkRouteAssociations(routeTables['RouteTableId'])
  if routeAssociations['Main']: 
    routeTableDispMain = "Yes"
  else:
    routeTableDispMain = "No"
  routeTableRptCommonLine = (routeTables['RouteTableId'], routeTables['VpcId'], routeTableDispMain, tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound)
  if aws_cleanupArg.inv:
    routeTableRpt.addLine(False, *routeTableRptCommonLine)
  elif tagData.delThisItem:
    routeTableRpt.addLine(False, *routeTableRptCommonLine)
    termTrack.x[termTrack.RouteTable][routeTables['RouteTableId']] = {'DISPLAY_ID': routeTables['RouteTableId'] + formatDispName(tagData.nameTag),'VpcId':routeTables['VpcId']}
if routeTableRpt.rows > 0:
  output += '\nRoute Tables{}:\n'.format(targetTagTitleInfo)
  output += routeTableRpt.result()  + "\n" * 2


#################################################################
#  InternetGateway
#################################################################
internetGatewayRpt = awsRpt(*[["Internet Gateway ID", 28],["Attached VPC", 25],["VPC Status",10],["Name(Tag)", 30],keepTagHeader,targetTagHeader])
for internetGateways  in clientEC2.describe_internet_gateways()['InternetGateways']:
  if internetGateways['Attachments']:
    internetGatewayDispVpcId = internetGateways['Attachments'][0]['VpcId']
    internetGatewayDispState = internetGateways['Attachments'][0]['State']
  else:
    internetGatewayDispVpcId = ''
    internetGatewayDispState = ''
  tagData = tagScan(internetGateways['Tags'] if 'Tags' in internetGateways else [], aws_cleanupArg)
  internetGatewayRptCommonLine = (internetGateways['InternetGatewayId'], internetGatewayDispVpcId, internetGatewayDispState, tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound)
  if aws_cleanupArg.inv:
    internetGatewayRpt.addLine(False, *internetGatewayRptCommonLine)
  elif tagData.delThisItem:
    internetGatewayRpt.addLine(False, *internetGatewayRptCommonLine)
    termTrack.x[termTrack.InternetGateway][internetGateways['InternetGatewayId']] = {'DISPLAY_ID': internetGateways['InternetGatewayId'] + formatDispName(tagData.nameTag),'VpcID':internetGatewayDispVpcId}
if internetGatewayRpt.rows > 0:
  output += '\nInternet Gateway{}:\n'.format(targetTagTitleInfo)
  output += internetGatewayRpt.result()  + "\n" * 2


#################################################################
#  Subnet
#################################################################
subnetRpt = awsRpt(*[["CIDR Block", 20],["Subnet ID", 28],["VPC ID", 25],["Name(Tag)", 30],keepTagHeader,targetTagHeader,["State", 10]])
for subnets in clientEC2.describe_subnets()['Subnets']:
  tagData = tagScan(subnets['Tags'] if 'Tags' in subnets else [], aws_cleanupArg)
  subnetRptCommonLine = (subnets['CidrBlock'], subnets['SubnetId'], subnets['VpcId'], tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,subnets['State'])
  if aws_cleanupArg.inv:
    subnetRpt.addLine(False, *subnetRptCommonLine)
  elif tagData.delThisItem:
    subnetRpt.addLine(False, *subnetRptCommonLine)
    termTrack.x[termTrack.Subnet][subnets['SubnetId']] = {'DISPLAY_ID': subnets['SubnetId'] + formatDispName(tagData.nameTag, subnets['CidrBlock'])}
if subnetRpt.rows > 0:
  output += '\nSubnet{}:\n'.format(targetTagTitleInfo)
  output += subnetRpt.result()  + "\n" * 2



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
    s3Rpt.addLine(False, buckets['Name'], tagData.keepTagFound, tagData.targetTagFound)
  elif tagData.delThisItem:
    s3Rpt.addLine(False, buckets['Name'], tagData.keepTagFound, tagData.targetTagFound)
    if not termTrack.x[termTrack.S3]:
      # Initialize termTrack.x[termTrack.S3] bucket list
      termTrack.x[termTrack.S3] = [buckets['Name']]
    else:
      termTrack.x[termTrack.S3].append(buckets['Name'])
if s3Rpt.rows > 0:
  output += '\nS3 Buckets{}:\n'.format(targetTagTitleInfo)
  output += s3Rpt.result()



print(output)
print("\n")
if not aws_cleanupArg.inv:
  if not termTrack.x:
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
    #  Having the user type in something more that just "yes" to confirm they really
    #  want to terminate/delete AWS item(s).
    verifyDelCode = str(random.randint(0, 9999)).zfill(4)
    print("\nWARNING: ALL AWS COMPONENTS LISTED ABOVE WILL BE TERMINATED/DELETED")
    print("Verification Code ---> {}".format(verifyDelCode))
    verifyTermProceed = input('Enter above 4-digit Verification Code to proceed (ctrl-c to exit): ')
    #################################################################
    #  EC2 Instances terminate
    #################################################################
    if verifyTermProceed == verifyDelCode:
      if termTrack.EC2 in termTrack.x:
        for currentRegion,idDict in termTrack.x[termTrack.EC2].items():
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
                response = ec2.Instance(id).terminate(DryRun=False)
                idDetail['TERMINATED'] = True
              except ClientError as e:
                print("    ERROR:", e, '\n')
        #  Loop through terminated instances and wait for the termination to 
        #  complete before continuing.
        for currentRegion,idDict in termTrack.x[termTrack.EC2].items():
          ec2 = boto3.resource('ec2',region_name=currentRegion)
          for id, idDetail in idDict.items():
            if idDetail['TERMINATED']:
              instance = ec2.Instance(id);
              print('Waiting for {0} EC2 instance {1} to terminate...'.format(currentRegion, idDetail['DISPLAY_ID']));
              instance.wait_until_terminated()

      #################################################################
      #  Security Groups delete
      #################################################################
      if termTrack.SecGroup in termTrack.x:
        #  Delete Security Groups
        for currentRegion,idDict in termTrack.x[termTrack.SecGroup].items():
          ec2 = boto3.resource('ec2',region_name=currentRegion)
          for id, idDetail in idDict.items():
            print('Deleting ' + currentRegion + ' Security Group ' + idDetail['DISPLAY_ID'])
            try:
              response = ec2.SecurityGroup(id).delete(DryRun=False)
            except ClientError as e:
              print("    ERROR:", e, '\n')
 
      #################################################################
      #  Volumes delete
      #################################################################
      if termTrack.Volume in termTrack.x:
        #  Delete Security Groups
        print("NOTE: Volumes may already been deleted with assoicated EC2 instances.")
        for currentRegion,idDict in termTrack.x[termTrack.Volume].items():
          clientEC2Region = boto3.client('ec2',region_name=currentRegion)
          for id, idDetail in idDict.items():
            print('Deleting ' + currentRegion + ' Volume ' + idDetail['DISPLAY_ID'])
            try:
              response = clientEC2Region.delete_volume(VolumeId = id, DryRun=False)
            except ClientError as e:
              if e.response["Error"]["Code"] == 'InvalidVolume.NotFound':
                print("    Volume already deleted")
              else:
                print("    ERROR:", e, '\n')


      #################################################################
      #  Key Pairs delete
      #################################################################
      if termTrack.KeyPairs in termTrack.x:
        for currentRegion,idDict in termTrack.x[termTrack.KeyPairs].items():
          ec2 = boto3.resource('ec2',region_name=currentRegion)
          for colData in idDict:
            print('Deleting Key Pair "' + colData + '"')
            try:
              response = ec2.KeyPair(colData).delete(DryRun=False)
            except ClientError as e:
              print("    ERROR:", e, '\n')


      #################################################################
      #  Route Tables delete
      #################################################################
      if termTrack.RouteTable in termTrack.x:
        for id, idDetail in termTrack.x[termTrack.RouteTable].items():
          print('Deleting Route Table {}'.format(idDetail['DISPLAY_ID']))
          delRouteTable = True
          #  Check main
          routeAssociations = chkRouteAssociations(id)
          if routeAssociations['Main']:
            if termTrack.VPC in termTrack.x and idDetail['VpcId'] in termTrack.x[termTrack.VPC]:
              print('  NOTE: {0} is the Main route table for VPC {1}, it is deleted automatically when VPC {1} is deleted.\n'.format(id, idDetail['VpcId']))
              delRouteTable = False
            else:
              print('    ERROR: {0} is the Main route table for VPC {1}, it cannot be deleted until VPC {1} is in-scope for deletion.'.format(id, idDetail['VpcId']))
          if delRouteTable:
            if routeAssociations['Subnets'] and not routeAssociations['Main']:
              print('  WARNING: subnet(s) {0} are associated with route table {1}.'.format(routeAssociations['Subnets'], id))
            try:
              ign = clientEC2.delete_route_table(RouteTableId=id)
            except ClientError as e:
              print("    ERROR:", e, '\n')

      #################################################################
      #  Internet Gateway delete
      #################################################################
      if termTrack.InternetGateway in termTrack.x:
        for id, idDetail in termTrack.x[termTrack.InternetGateway].items():
          error_detach_internet_gateway = False
          if idDetail['VpcID']:
            print('>> Detaching Internet Gateway {0} from VPC ID {1}'.format(idDetail['DISPLAY_ID'], idDetail['VpcID']))
            try:
              ign = clientEC2.detach_internet_gateway(InternetGatewayId=id,VpcId=idDetail['VpcID'])
            except ClientError as e:
              print("    ERROR:", e, '\n')
              error_detach_internet_gateway = True
          if not error_detach_internet_gateway:
            print('Deleting Internet Gateway {}'.format(idDetail['DISPLAY_ID']))
            try:
              ign = clientEC2.delete_internet_gateway(InternetGatewayId=id)
            except ClientError as e:
              print("    ERROR:", e, '\n')


      #################################################################
      #  Subnet delete
      #################################################################
      if termTrack.Subnet in termTrack.x:
        for id, idDetail in termTrack.x[termTrack.Subnet].items():
          print('Deleting Subnet {}'.format(idDetail['DISPLAY_ID']))
          try:
            ign = clientEC2.delete_subnet(SubnetId=id)
          except ClientError as e:
            print("    ERROR:", e, '\n')
 
      #################################################################
      #  VPC delete
      #################################################################
      if termTrack.VPC in termTrack.x:
        for id, idDetail in termTrack.x[termTrack.VPC].items():
          print('Deleting VPC {}'.format(idDetail['DISPLAY_ID']))
          #  Trap a couple simple error conditions. Provide warnings & explanation
          conflictList = []
          for idChk in clientEC2.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [id]}])['InternetGateways']:
            conflictList.append(idChk['InternetGatewayId'])
          if conflictList:
            print('  WARNING: VPC {0} is attached to the following gateway(s): {1}'.format(id, ', '.join(conflictList)))

          conflictList = []
          for idChk in clientEC2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [id]}])['Subnets']:
            conflictList.append(idChk['SubnetId'])
          if conflictList:
            print('  WARNING: VPC {0} is associated with the following subnet(s): {1}'.format(id, ', '.join(conflictList)))

          conflictList = []
          for idChk in clientEC2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values':[id]}])['RouteTables']:
            routeAssociations = chkRouteAssociations(idChk['RouteTableId'])
            if not routeAssociations['Main']:
              conflictList.append(idChk['RouteTableId'])
          if conflictList:
            print('  WARNING: VPC {0} is associated with the following route table(s): {1}'.format(id, ', '.join(conflictList)))

          conflictList = []
          for instResvChk in clientEC2.describe_instances(Filters=[{'Name': 'vpc-id', 'Values': [id]}])['Reservations']:
            for instChk in instResvChk['Instances']:
              conflictList.append(instChk['InstanceId'])
          if conflictList:
            print('  WARNING: VPC {0} is associated with the following EC2 instance(s): {1}'.format(id, ', '.join(conflictList)))

          try:
            ign = clientEC2.delete_vpc(VpcId=id)
          except ClientError as e:
            print("    ERROR:", e, '\n')

      #################################################################
      #  S3 buckets delete
      #################################################################
      if termTrack.S3 in termTrack.x:
        s3 = boto3.resource('s3')
        for bucketName in termTrack.x[termTrack.S3]:
          #  Before a bucket can be deleted, the objects in the bucket first have to be
          #  deleted.
          print('Deleting any objects contained in S3 Bucket ' + bucketName + '...')
          try:
            ign = s3.Bucket(bucketName).objects.delete()
          except ClientError as e:
            print("   ERROR: ", e, '\n')
          print('Deleting S3 Bucket ' + bucketName)
          try:
            ign = s3.Bucket(bucketName).delete()
          except ClientError as e:
            print("   ERROR:", e, '\n')
        
    else:
      print('Invalid Verification Code entered. Exiting script WITHOUT terminating/deleting AWS components')
