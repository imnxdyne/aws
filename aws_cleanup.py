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
#  2018.07.23 - ww - Shifted variables that could be updated by end-user to external file
#                    aws_cleanup_import.py (could be convinced to place these variables back into
#                    this script). Corrected subnets order in deletion. Changed
#                    argument storage from class to namedtuple.
import sys
import os
import re
import random
import signal
try:
  import boto3
except ImportError as e:
  print('This script requires Boto3 to be installed and configured.')
  print('Can install via "pip install boto3"')
  exit(1)
import argparse
import io
import textwrap
from botocore.exceptions import ClientError,NoCredentialsError,EndpointConnectionError
from collections import deque,defaultdict,namedtuple    # used for initializing nested dictionaries
try:
  from aws_cleanup_import import constantKeepTag, componentDef, awsComponentClass, aws_cleanup_import_ver
except ImportError:
  print('ERROR: aws_cleanup_import.py is missing. This file is required')
  exit(1)

def signal_handler(sig, frame):
        print('\nTERMINATING SCRIPT')
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

aws_cleanup_main_ver = 2.5
if aws_cleanup_import_ver != aws_cleanup_main_ver:
  print('WARNING: incorrect version of aws_cleanup_import.py file (version number is {0}; expected {1}).'.format(aws_cleanup_import_ver, aws_cleanup_main_ver))
  ign = input('Press enter to continue: ')

#  Setting up a named tuple for consolidating all the arguments passed plus a location
#  to store the normalized targetTag & keepTag. Believe that Python 3.7 has a better
#  method for defining the "default".
scriptArgsTuple = namedtuple('scriptArgsTuple', ['inv', 'del_tag', 'del_all', 'targetTag', 'keepTag'])
scriptArgsTuple.__new__.__defaults__ = (False, False, False, None, constantKeepTag)

def signal_handler(sig, frame):
        print('\nTERMINATING SCRIPT')
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

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


def chkRouteAssociations(parRouteId, parScriptArg):
  #  Digging through the route table associations to see if the route table is set as 'Main' 
  #  was repeated in a couple areas - easier to have as a function and include any
  #  associated subnets.
  clientEC2Route = boto3.client('ec2')
  routeTableIsMain = False
  routeTableSubnets = []

  for idChk in clientEC2Route.describe_route_tables(Filters=[{'Name': 'route-table-id', 'Values':[parRouteId]}])['RouteTables']:
    if idChk['Associations']:
      for chkAssociations in idChk['Associations']:
        if chkAssociations.get('Main'):
          routeTableIsMain = True
        if chkAssociations.get('SubnetId'):
          subnetInfo = clientEC2Route.describe_subnets(Filters=[{'Name':'subnet-id', 'Values':[chkAssociations['SubnetId']]}])['Subnets'][0]
          routeTableSubnets.append(chkAssociations['SubnetId'] + tagNameFind(subnetInfo.get('Tags'), parScriptArg))
  return{'Main': routeTableIsMain, 'Subnets': routeTableSubnets}

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

def tagNameFind(parTagList, parScriptArg):
  if parTagList is None:
    parTagList = []
  nameTagValue = dispKeepTagKeyList = ""
  keepTagKeyList = []
  for t in parTagList:
    if t['Key'] == 'Name':
      nameTagValue = t.get('Value')
    else:
      for searchKeepTag in parScriptArg.keepTag:
        if re.search('^'+re.escape(searchKeepTag)+'$', t.get('Key'), re.IGNORECASE):
          keepTagKeyList.append(t.get('Key'))
  if keepTagKeyList:
    dispKeepTagKeyList = " [{0}]".format(', '.join(keepTagKeyList))
  if nameTagValue or dispKeepTagKeyList:
    nameTag = " ({0}{1})".format(nameTagValue, keepTagKeyList)
  else:
    nameTag = "" 
  return nameTag
  
class tagScan:
  #  tagScan contains AWS item object's derived attributes (at least as much as could be
  #  derived).
  def __init__(self, parTagList, parScriptArg):
    #  If parTagList is none, set as empty list to bypass for-loop.
    if parTagList is None:
      parTagList = []
    self.nameTag = ""
    self.delThisItem = False
    if parScriptArg.targetTag is None:
      self.targetTagFound = None
    else:
      self.targetTagFound = ""
    self.keepTagFound = ""
    for t in parTagList:
      if t['Key'] == 'Name':
        self.nameTag = t['Value']
      else:
        thisTagIsKeep = False
        if parScriptArg.keepTag is not None:
          for searchKeepTag in parScriptArg.keepTag:
            if re.search('^'+re.escape(searchKeepTag)+'$', t['Key'], re.IGNORECASE):
              self.keepTagFound = "Yes"
              thisTagIsKeep = True
        if not thisTagIsKeep and parScriptArg.targetTag is not None:
          for searchTag in parScriptArg.targetTag:
            if re.search('^'+re.escape(searchTag)+'$', t['Key'], re.IGNORECASE):
              if self.targetTagFound:
                self.targetTagFound += ", " + searchTag
              else:
                self.targetTagFound = searchTag
    if not self.keepTagFound:
      if parScriptArg.del_all:
        self.delThisItem = True
      elif parScriptArg.del_tag and self.targetTagFound:
        self.delThisItem = True
        
argUsage = "usage: aws_cleanup.py -[h][--del][--tag <tag_key1> [<tag_key2> [tag_key# ..]]]"
parser = argparse.ArgumentParser(allow_abbrev=False,usage=argUsage)
#  As "del" is a reserved word in Python, needed to have an alnternate destination.
parser.add_argument('-d', '--del', dest='delete', help='delete/terminate AWS components', action="store_true", default=False)
parser.add_argument('-t', '--tag', nargs='+', help='search for components with a specific key value')
parser.add_argument('--test_region', help='reduces number of in-scope regions for code testing for better performance -wfw', action="store_true", default=False)
args = parser.parse_args()
#  Normalize and evaluate args.tag list for errors:
if args.tag is not None:
  #  Remove any blank tags
  tagEx = re.compile('^\s*$')
  args.tag = [tag for tag in args.tag if not tagEx.match(tag)]

  #  Remove any duplicates
  args.tag = list(set(args.tag))
  #  If args.tag was used but contains no data, raise an error
  if len(args.tag) == 0:
    print(argUsage)
    print("aws_cleanup.py: error: argument --tag: expected at least one argument")
    exit(5)

  #  Raise an error if any of the tag arguments are "keep" values.
  errArgsKeepTag = False
  for inspArgsTag in args.tag:
    for inspKeepTag in constantKeepTag:
      if re.search('^'+re.escape(inspKeepTag)+'$', inspArgsTag, re.IGNORECASE):
        print('\nERROR: --tag cannot include the value "{0}".\nThe tag key "{0}" is used to identify which AWS items can\'t be terminated or deleted.'.format(inspKeepTag))
        errArgsKeepTag = True
  if errArgsKeepTag:
    exit(6)
if args.delete:
  if args.tag:
    aws_cleanupArg = scriptArgsTuple(del_tag=True, targetTag=args.tag)
  else:
    aws_cleanupArg = scriptArgsTuple(del_all=True)
else:
  aws_cleanupArg = scriptArgsTuple(inv=True, targetTag=args.tag)

if aws_cleanupArg.targetTag:
  targetTagHeader = ["Search Tag",18,"<"]
  targetTagTitleInfo = ' (search tag "{}")'.format('", "'.join(aws_cleanupArg.targetTag))
else:
  targetTagHeader = None
  targetTagTitleInfo = ''

keepTagHeader = [', '.join(aws_cleanupArg.keepTag)+"(Tag)","","^"]

awsComponent = awsComponentClass()
# Initialize the dictionary of items to delete/terminate
termTrack = defaultdict(lambda : defaultdict(dict))
noDeleteList = []
print('AWS components in-scope for {}:'.format(sys.argv[0]))
for id, idDetail in vars(awsComponent).items():
  if type(idDetail) is componentDef:
    print('  * {0} {1}'.format(idDetail.compName, ('' if idDetail.compDelete or aws_cleanupArg.inv else '\t*** DELETE DISABLED ***')))
    if not (aws_cleanupArg.inv or idDetail.compDelete):
      noDeleteList.append(idDetail.compName)
if aws_cleanupArg.keepTag:
  print('Tag used to identify which AWS items can\'t be terminated or deleted: {0}'.format(', '.join(aws_cleanupArg.keepTag)))
print("\n")
# Load all regions from AWS into region list.
# As this is where the initial connection occurs to AWS, included a couple traps to handle
# connectivity errors - network MIA, invalid AWS credentials, missing AWS credentials,....
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
print('Inventory of ALL AWS components\n')
output=""
securityGroupDepend=defaultdict(lambda : defaultdict(dict))
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
  #  ...CompSci truth tables from WWU...
  if aws_cleanupArg.inv or awsComponent.EC2.compDelete:
    for resp in clientEC2Region.describe_instances()['Reservations']:
      for inst in resp['Instances']:
        tagData = tagScan(inst.get('Tags'), aws_cleanupArg)
        if aws_cleanupArg.inv:
          ec2Rpt.addLine(regionBreakEC2.lineBreak(currentRegion), currentRegion, inst['InstanceId'],tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,inst['ImageId'],inst['State']['Name'])
        elif inst['State']['Name'] != 'terminated':
          if tagData.delThisItem:
            ec2Rpt.addLine(regionBreakEC2.lineBreak(currentRegion), currentRegion, inst['InstanceId'],tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,inst['ImageId'],inst['State']['Name'])
            termTrack[awsComponent.EC2][currentRegion][inst['InstanceId']] = {'DISPLAY_ID': inst['InstanceId'] + formatDispName(tagData.nameTag),'TERMINATED':False}

  #################################################################
  #  Security Group
  #################################################################
  if 'secGroupRpt' not in globals():
    secGroupRpt = awsRpt(*[["Region", 16],["Group ID", 25],["Name(Tag)", 30],keepTagHeader,targetTagHeader,["Group Name", 30],["Description", 35]])
  if aws_cleanupArg.inv or awsComponent.SecGroup.compDelete:
    for resp in clientEC2Region.describe_security_groups()['SecurityGroups']:
      # ... can't do anything with the default security group
      if resp['GroupName'] != 'default':
        tagData = tagScan(resp.get('Tags'), aws_cleanupArg)
        secGroupRptCommonLine = (currentRegion, resp['GroupId'],tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,resp['GroupName'],resp['Description'])
        if aws_cleanupArg.inv:
          secGroupRpt.addLine(regionBreakSecGroup.lineBreak(currentRegion), *secGroupRptCommonLine)
        elif tagData.delThisItem:
          secGroupRpt.addLine(regionBreakSecGroup.lineBreak(currentRegion), *secGroupRptCommonLine)
          termTrack[awsComponent.SecGroup][currentRegion][resp['GroupId']] = {'DISPLAY_ID': resp['GroupId'] + formatDispName(tagData.nameTag, resp['GroupName'], resp['Description'])}
          

  #################################################################
  #  Volumes
  #################################################################
  if 'volRpt' not in globals():
    volRpt = awsRpt(*[["Region", 16],["Volume ID", 25],["Name(Tag)", 30],keepTagHeader,targetTagHeader,["Vol Type", 10],["State", 15]])
  if aws_cleanupArg.inv or awsComponent.Volume.compDelete:
    for vol in clientEC2Region.describe_volumes()['Volumes']:
      tagData = tagScan(vol.get('Tags'), aws_cleanupArg)
      volRptCommonLine = (currentRegion, vol['VolumeId'],tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,vol['VolumeType'],vol['State'])
      if aws_cleanupArg.inv:
        volRpt.addLine(regionBreakVolume.lineBreak(currentRegion), *volRptCommonLine)
      elif tagData.delThisItem:
        volRpt.addLine(regionBreakVolume.lineBreak(currentRegion), *volRptCommonLine)
        termTrack[awsComponent.Volume][currentRegion][vol['VolumeId']] = {'DISPLAY_ID': vol['VolumeId'] + formatDispName(tagData.nameTag)}

  #################################################################
  #  Key Pairs
  #################################################################
  if 'secKeyPairsRpt' not in globals():
    secKeyPairsRpt = awsRpt(*[["Region", 16],["KeyName", 30]])
  if aws_cleanupArg.inv or awsComponent.KeyPairs.compDelete:
    # Skipping key pairs if deleting by tags (as they have no tags)
    if not aws_cleanupArg.del_tag:
      for resp in clientEC2Region.describe_key_pairs()['KeyPairs']:
        if aws_cleanupArg.inv:
          secKeyPairsRpt.addLine(regionBreakKeyPairs.lineBreak(currentRegion), currentRegion, resp['KeyName'])
        else:
          secKeyPairsRpt.addLine(regionBreakKeyPairs.lineBreak(currentRegion), currentRegion, resp['KeyName'])
          if not termTrack[awsComponent.KeyPairs][currentRegion]:
            termTrack[awsComponent.KeyPairs][currentRegion] = [resp['KeyName']]
          else:
            termTrack[awsComponent.KeyPairs][currentRegion].append(resp['KeyName'])

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
if aws_cleanupArg.inv or awsComponent.VPC.compDelete:
  for vpcs in clientEC2.describe_vpcs()['Vpcs']:
    tagData = tagScan(vpcs.get('Tags'), aws_cleanupArg)
    vpcsRptCommonLine = (vpcs['CidrBlock'], vpcs['VpcId'], tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,vpcs['State'])
    if aws_cleanupArg.inv:
      vpcRpt.addLine(False, *vpcsRptCommonLine)
    elif tagData.delThisItem:
      vpcRpt.addLine(False, *vpcsRptCommonLine)
      termTrack[awsComponent.VPC][vpcs['VpcId']] = {'DISPLAY_ID': vpcs['VpcId'] + formatDispName(tagData.nameTag, vpcs['CidrBlock'])}
if vpcRpt.rows > 0:
  output += '\nVPC{}:\n'.format(targetTagTitleInfo)
  output += vpcRpt.result()  + "\n" * 2

#################################################################
#  Route Table
#################################################################
routeTableRpt = awsRpt(*[["Route Table ID", 28],["VPC ID", 25],["Main", 4],["Name(Tag)", 30],keepTagHeader,targetTagHeader])
if aws_cleanupArg.inv or awsComponent.RouteTable.compDelete:
  for routeTables in clientEC2.describe_route_tables()['RouteTables']:
    tagData = tagScan(routeTables.get('Tags'), aws_cleanupArg)
    routeAssociations = chkRouteAssociations(routeTables['RouteTableId'], aws_cleanupArg)
    if routeAssociations['Main']: 
      routeTableDispMain = "Yes"
    else:
      routeTableDispMain = "No"
    routeTableRptCommonLine = (routeTables['RouteTableId'], routeTables['VpcId'], routeTableDispMain, tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound)
    if aws_cleanupArg.inv:
      routeTableRpt.addLine(False, *routeTableRptCommonLine)
    elif tagData.delThisItem:
      routeTableRpt.addLine(False, *routeTableRptCommonLine)
      termTrack[awsComponent.RouteTable][routeTables['RouteTableId']] = {'DISPLAY_ID': routeTables['RouteTableId'] + formatDispName(tagData.nameTag),'VpcId':routeTables['VpcId']}
if routeTableRpt.rows > 0:
  output += '\nRoute Tables{}:\n'.format(targetTagTitleInfo)
  output += routeTableRpt.result()  + "\n" * 2


#################################################################
#  InternetGateway
#################################################################
internetGatewayRpt = awsRpt(*[["Internet Gateway ID", 28],["Attached VPC", 25],["VPC Status",10],["Name(Tag)", 30],keepTagHeader,targetTagHeader])
if aws_cleanupArg.inv or awsComponent.InternetGateway.compDelete:
  for internetGateways  in clientEC2.describe_internet_gateways()['InternetGateways']:
    if internetGateways['Attachments']:
      internetGatewayDispVpcId = internetGateways['Attachments'][0]['VpcId']
      internetGatewayDispState = internetGateways['Attachments'][0]['State']
    else:
      internetGatewayDispVpcId = ''
      internetGatewayDispState = ''
    tagData = tagScan(internetGateways.get('Tags'), aws_cleanupArg)
    internetGatewayRptCommonLine = (internetGateways['InternetGatewayId'], internetGatewayDispVpcId, internetGatewayDispState, tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound)
    if aws_cleanupArg.inv:
      internetGatewayRpt.addLine(False, *internetGatewayRptCommonLine)
    elif tagData.delThisItem:
      internetGatewayRpt.addLine(False, *internetGatewayRptCommonLine)
      termTrack[awsComponent.InternetGateway][internetGateways['InternetGatewayId']] = {'DISPLAY_ID': internetGateways['InternetGatewayId'] + formatDispName(tagData.nameTag),'VpcID':internetGatewayDispVpcId}
if internetGatewayRpt.rows > 0:
  output += '\nInternet Gateway{}:\n'.format(targetTagTitleInfo)
  output += internetGatewayRpt.result()  + "\n" * 2


#################################################################
#  Subnet
#################################################################
subnetRpt = awsRpt(*[["CIDR Block", 20],["Subnet ID", 28],["VPC ID", 25],["Name(Tag)", 30],keepTagHeader,targetTagHeader,["State", 10]])
if aws_cleanupArg.inv or awsComponent.Subnet.compDelete:
  for subnets in clientEC2.describe_subnets()['Subnets']:
    tagData = tagScan(subnets.get('Tags'), aws_cleanupArg)
    subnetRptCommonLine = (subnets['CidrBlock'], subnets['SubnetId'], subnets['VpcId'], tagData.nameTag,tagData.keepTagFound,tagData.targetTagFound,subnets['State'])
    if aws_cleanupArg.inv:
      subnetRpt.addLine(False, *subnetRptCommonLine)
    elif tagData.delThisItem:
      subnetRpt.addLine(False, *subnetRptCommonLine)
      termTrack[awsComponent.Subnet][subnets['SubnetId']] = {'DISPLAY_ID': subnets['SubnetId'] + formatDispName(tagData.nameTag, subnets['CidrBlock'])}
if subnetRpt.rows > 0:
  output += '\nSubnet{}:\n'.format(targetTagTitleInfo)
  output += subnetRpt.result()  + "\n" * 2



#################################################################
#  S3 Buckets
#################################################################
s3Rpt = awsRpt(*[["Bucket Name", 40],keepTagHeader,targetTagHeader])
if aws_cleanupArg.inv or awsComponent.S3.compDelete:
  clientS3 = boto3.client('s3')
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
      if not termTrack[awsComponent.S3]:
        # Initialize termTrack[awsComponent.S3] bucket list
        termTrack[awsComponent.S3] = [buckets['Name']]
      else:
        termTrack[awsComponent.S3].append(buckets['Name'])
if s3Rpt.rows > 0:
  output += '\nS3 Buckets{}:\n'.format(targetTagTitleInfo)
  output += s3Rpt.result()



print(output)
print("\n")
if not aws_cleanupArg.inv:
  if not termTrack:
    print("No AWS items were found that were in-scope for terminating/deleting")
    if aws_cleanupArg.del_tag:
      print('Search tag: "{}"'.format('", "'.join(aws_cleanupArg.targetTag)))
  else:
    #  Verify that they really want to terminate/delete everything listed as in-scope.
    if aws_cleanupArg.del_all:
      print("Terminating/deleting ALL components")
    else:
      print('Deleting items with the tag(s): "' + '", "'.join(aws_cleanupArg.targetTag) + '"')
    if noDeleteList:
      print('REMEMBER - DELETION/TERMINATION HAS BEEN DISABLED FOR THE FOLLOWING AWS COMPONENTS:\n\t{}'.format('\n\t'.join(noDeleteList)))
    #  Having the user type in something more that just "yes" to confirm they really
    #  want to terminate/delete AWS item(s).
    verifyDelCode = str(random.randint(0, 9999)).zfill(4)
    print("\nALL AWS COMPONENTS LISTED ABOVE WILL BE TERMINATED/DELETED. Verification Code ---> {}".format(verifyDelCode))
    verifyTermProceed = input('Enter above 4-digit Verification Code to proceed (ctrl-c to exit): ')
    #################################################################
    #  EC2 Instances terminate
    #################################################################
    if verifyTermProceed == verifyDelCode:
      if awsComponent.EC2 in termTrack:
        for currentRegion,idDict in termTrack[awsComponent.EC2].items():
          ####wfw ####ec2 = boto3.resource('ec2',region_name=currentRegion)
          clientEC2Region = boto3.client('ec2',region_name=currentRegion)

          for id, idDetail in idDict.items():
            print('Terminating ' + currentRegion + ' EC2 instance ' + idDetail['DISPLAY_ID'])
            ec2DryRunSuccessful=False
            #  Not sure if there's an advantage to having the DryRun test;
            #  will leave this segment of code in place for future.
            try:
              response = clientEC2Region.terminate_instances(InstanceIds=[id], DryRun=True)
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
                response = clientEC2Region.terminate_instances(InstanceIds=[id], DryRun=False)
                idDetail['TERMINATED'] = True
              except ClientError as e:
                print("    ERROR:", e, '\n')
        #  Loop through terminated instances and wait for the termination to 
        #  complete before continuing.
        for currentRegion,idDict in termTrack[awsComponent.EC2].items():
          clientEC2Region = boto3.client('ec2',region_name=currentRegion)
          waiter = clientEC2Region.get_waiter('instance_terminated')
          for id, idDetail in idDict.items():
            if idDetail['TERMINATED']:
              print('Waiting for {0} EC2 instance {1} to terminate...'.format(currentRegion, idDetail['DISPLAY_ID']));
              waiter.wait(InstanceIds=[id])
              
      #################################################################
      #  Security Groups delete
      #################################################################
      if awsComponent.SecGroup in termTrack:
        #  Delete Security Groups
        for currentRegion,idDict in termTrack[awsComponent.SecGroup].items():
          clientEC2Region = boto3.client('ec2',region_name=currentRegion)
          for id, idDetail in idDict.items():
            print('Deleting ' + currentRegion + ' Security Group ' + idDetail['DISPLAY_ID'])
            conflictList = []
            for instResvChk in clientEC2Region.describe_instances(Filters=[{'Name': 'instance.group-id', 'Values': [id]}])['Reservations']:
              for instChk in instResvChk['Instances']:
                conflictList.append(instChk['InstanceId'] + tagNameFind(instChk.get('Tags'), aws_cleanupArg))
            if conflictList:
              print('  WARNING: Security Group {0} is attached to the following EC2 instance(s):\n\t{1}'.format(id, '\n\t'.join(conflictList)))
            try:
              response = clientEC2Region.delete_security_group(GroupId = id, DryRun=False)
            except ClientError as e:
              print("    ERROR:", e, '\n')

      #################################################################
      #  Volumes delete
      #################################################################
      if awsComponent.Volume in termTrack:
        #  Delete Security Groups
        print("NOTE: Volumes may already been deleted with assoicated EC2 instances.")
        for currentRegion,idDict in termTrack[awsComponent.Volume].items():
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
      if awsComponent.KeyPairs in termTrack:
        for currentRegion,idDict in termTrack[awsComponent.KeyPairs].items():
          ec2 = boto3.resource('ec2',region_name=currentRegion)
          for colData in idDict:
            print('Deleting Key Pair "' + colData + '"')
            try:
              response = ec2.KeyPair(colData).delete(DryRun=False)
            except ClientError as e:
              print("    ERROR:", e, '\n')

      #################################################################
      #  Subnet delete
      #################################################################
      if awsComponent.Subnet in termTrack:
        for id, idDetail in termTrack[awsComponent.Subnet].items():
          print('Deleting Subnet {}'.format(idDetail['DISPLAY_ID']))
          conflictList = []
          for instResvChk in clientEC2.describe_instances(Filters=[{'Name': 'subnet-id', 'Values': [id]}])['Reservations']:
            for instChk in instResvChk['Instances']:
              conflictList.append(instChk['InstanceId'] + tagNameFind(instChk.get('Tags'), aws_cleanupArg))
          if conflictList:
            print('  WARNING: subnet {0} is associated with the following EC2 instance(s):\n\t{1}'.format(id, '\n\t'.join(conflictList)))

          try:
            ign = clientEC2.delete_subnet(SubnetId=id)
          except ClientError as e:
            print("    ERROR:", e, '\n')

      #################################################################
      #  Route Tables delete
      #################################################################
      if awsComponent.RouteTable in termTrack:
        for id, idDetail in termTrack[awsComponent.RouteTable].items():
          print('Deleting Route Table {}'.format(idDetail['DISPLAY_ID']))
          delRouteTable = True
          #  Check main
          routeAssociations = chkRouteAssociations(id, aws_cleanupArg)
          if routeAssociations['Main']:
            chkVpc = clientEC2.describe_vpcs(VpcIds=[idDetail['VpcId']])['Vpcs'][0]
            if awsComponent.VPC in termTrack and idDetail['VpcId'] in termTrack[awsComponent.VPC]:
              print('  NOTE: {0} is the Main route table for VPC {1}; it\'s deleted automatically when the VPC is deleted.\n'.format(id, idDetail['VpcId'] + tagNameFind(chkVpc.get('Tags'), aws_cleanupArg)))
              delRouteTable = False
            else:
              print('  WARNING: {0} is the Main route table for VPC {1}; it cannot be deleted until the VPC is in-scope for deletion.'.format(id, idDetail['VpcId']  + tagNameFind(chkVpc.get('Tags'), aws_cleanupArg)))
          if delRouteTable:
            if routeAssociations['Subnets'] and not routeAssociations['Main']:
              print('  WARNING: Route Table {0} is associated with the following subnets:\n\t{1}.'.format(id, '\n\t'.join(routeAssociations['Subnets'])))
            try:
              ign = clientEC2.delete_route_table(RouteTableId=id)
            except ClientError as e:
              print("    ERROR:", e, '\n')

      #################################################################
      #  Internet Gateway delete
      #################################################################
      if awsComponent.InternetGateway in termTrack:
        for id, idDetail in termTrack[awsComponent.InternetGateway].items():
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
      #  VPC delete
      #################################################################
      if awsComponent.VPC in termTrack:
        for id, idDetail in termTrack[awsComponent.VPC].items():
          print('Deleting VPC {}'.format(idDetail['DISPLAY_ID']))
          #  Trap a couple simple error conditions. Provide warnings & explanation
          conflictList = []
          for idChk in clientEC2.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [id]}])['InternetGateways']:
            conflictList.append(idChk['InternetGatewayId'] + tagNameFind(idChk.get('Tags'), aws_cleanupArg))
          if conflictList:
            print('  WARNING: VPC {0} is attached to the following gateway(s):\n\t{1}'.format(id, '\n\t'.join(conflictList)))

          conflictList = []
          for idChk in clientEC2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [id]}])['Subnets']:
            conflictList.append(idChk['SubnetId']  + tagNameFind(idChk.get('Tags'), aws_cleanupArg))
          if conflictList:
            print('  WARNING: VPC {0} is associated with the following subnet(s):\n\t{1}'.format(id, '\n\t'.join(conflictList)))

          conflictList = []
          for idChk in clientEC2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values':[id]}])['RouteTables']:
            routeAssociations = chkRouteAssociations(idChk['RouteTableId'], aws_cleanupArg)
            if not routeAssociations['Main']:
              conflictList.append(idChk['RouteTableId']  + tagNameFind(idChk.get('Tags'), aws_cleanupArg))
          if conflictList:
            print('  WARNING: VPC {0} is associated with the following route table(s):\n\t{1}'.format(id, '\n\t'.join(conflictList)))

          conflictList = []
          for instResvChk in clientEC2.describe_instances(Filters=[{'Name': 'vpc-id', 'Values': [id]}])['Reservations']:
            for instChk in instResvChk['Instances']:
              conflictList.append(instChk['InstanceId'] + tagNameFind(instChk.get('Tags'), aws_cleanupArg))
          if conflictList:
            print('  WARNING: VPC {0} is associated with the following EC2 instance(s):\n\t{1}'.format(id, '\n\t'.join(conflictList)))

          try:
            ign = clientEC2.delete_vpc(VpcId=id)
          except ClientError as e:
            print("    ERROR:", e, '\n')

      #################################################################
      #  S3 buckets delete
      #################################################################
      if awsComponent.S3 in termTrack:
        s3 = boto3.resource('s3')
        for bucketName in termTrack[awsComponent.S3]:
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
