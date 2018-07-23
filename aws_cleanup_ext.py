# aws_cleanup_ext.py
#   Consolidated location for "global vars" that may be modified by end-user.
#   2.5: baseline
from collections import deque,defaultdict,namedtuple  

#  aws_cleanup_ext_ver needs to match version number in aws_cleanup.py
aws_cleanup_ext_ver = 2.5

#  Can enabled multiple "keep" tags.
constantKeepTag = ['keep']

componentDef = namedtuple("componentDef", ['compName', 'compDelete'])
class awsComponentClass:
  def __init__(self):
    #  compName - utilized for the following:
    #    1) Unique dictionary index for termTrackClass attribute "x"
    #    2) Title / display name
    #  compDelete: flag to disable AWS component from being deleted, but will still
    #       display inventory. Used for testing or keeping AWS components
    #
    self.EC2 = componentDef(compName = 'EC2 instances', compDelete = True)
    self.SecGroup = componentDef(compName = 'Security Groups', compDelete = True)
    self.Volume = componentDef(compName = 'Volumes', compDelete = True)
    self.KeyPairs = componentDef(compName = 'Key Pairs', compDelete = True)
    self.S3 = componentDef(compName = 'S3 Buckets', compDelete = True)
    self.VPC = componentDef(compName = 'VPC', compDelete = True)
    self.Subnet = componentDef(compName = 'Subnets', compDelete = True)
    self.InternetGateway = componentDef(compName = 'Internet Gateways', compDelete = True)
    self.RouteTable = componentDef(compName = 'Route Tables', compDelete = True)

