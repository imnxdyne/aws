# aws_cleanup_import.py
#   Consolidated location for "global vars" that may be modified by end-user.
from collections import deque,defaultdict,namedtuple  

#  aws_cleanup_import_ver needs to match version number in aws_cleanup.py
aws_cleanup_import_ver = 2.8

#  Can enabled multiple "keep" tags.
constantKeepTag = ['keep']

componentDef = namedtuple("componentDef", ['compName', 'compDelete', 'itemsKeep'])
componentDef.__new__.__defaults__ = (None, None, ())
class awsComponentClass:
  def __init__(self):
    #  compName - used for script (no need to change):
    #    1) Unique dictionary index for termTrackClass attribute "x"
    #    2) Title / display name
    #
    #  compDelete: disables deletion of AWS component (inventory will still be displayed).
    #     "compDelete = True": delete AWS component
    #     "compDelete = False": don't delete AWS component
    #     Examples:
    #       >>> Block aws_cleanup.py from deleting AWS user accounts (compDelete = False):
    #         self.User = componentDef(compName='User', compDelete = False, itemsKeep=())
    #       >>> AWS user accounts are in-scope for deletion by aws_cleanup.py script (compDelete = True):
    #         self.User = componentDef(compName='User', compDelete = True, itemsKeep=())
    #
    #    itemsKeep: list of AWS item names to exclude from deletion. Targeted for AWS components that don't
    #         have tags (no "keep" tag). Item list are case-insensetive, quoted, and separated by commas:
    #     Example:
    #       >>> Block AWS key pairs with the names 'ABC' or 'XYZ' from being deleted:
    #         self.KeyPairs = componentDef(compName = 'Key Pairs', compDelete = True, itemsKeep=('ABC', 'xyz'))
    #       >>> Block user 'Scott' from being deleted:
    #         self.User = componentDef(compName = 'User', compDelete = True, itemsKeep=('Scott'))

    self.EC2 = componentDef(compName = 'EC2 Instances', compDelete=True )
    self.SecurityGroups = componentDef(compName = 'Security Groups', compDelete=True )
    #  NOTE: Changing compDelete = False for Volumes will not have any affect on volumes attached
    #        to an EC2 instance. When the EC2 instance is deleted, the volume will automatically be dropped.
    self.Volumes = componentDef(compName = 'Volumes', compDelete=True )
    self.KeyPairs = componentDef(compName = 'Key Pairs', compDelete=True, itemsKeep=() )
    self.MetricAlarms = componentDef(compName = 'Metric Alarms', compDelete=True, itemsKeep=() )
    self.ConfigRules = componentDef(compName = 'Config Rules', compDelete=True, itemsKeep=() )
    self.ConfigurationRecorders = componentDef(compName = 'Configuration Recorder', compDelete=True, itemsKeep=() )
    self.CloudFormationStacks = componentDef(compName = 'CloudFormation Stacks', compDelete=True, itemsKeep=() )
    self.CloudTrail = componentDef(compName = 'Cloud Trail', compDelete=True, itemsKeep=() )
    self.CloudWatchLogGroups = componentDef(compName = 'Cloud Watch Log Group', compDelete=True, itemsKeep=() )
    self.AssessmentTargets = componentDef(compName = 'Assessment Targets', compDelete=True, itemsKeep=() )	#itemsKeep=('assessmentTargetName1',...)
    self.SNSTopics = componentDef(compName = 'SNS Topic', compDelete=True, itemsKeep=() )
    self.S3 = componentDef(compName = 'S3 Buckets', compDelete=True)
    self.VPC = componentDef(compName = 'VPC', compDelete=True)
    self.Subnets = componentDef(compName = 'Subnets (non-default)', compDelete=True)
    self.InternetGateways = componentDef(compName = 'Internet Gateways', compDelete=True)
    self.RouteTables = componentDef(compName = 'Route Tables', compDelete=True)
    self.VPCEndpoints = componentDef(compName = 'VPC Endpoints', compDelete=True, itemsKeep=() ) 	#itemsKeep=('vpce-....') - list of Endpoint IDs
    self.Users = componentDef(compName = 'User', compDelete=True, itemsKeep=() ) 	#itemsKeep=('Username1','Username2',...) 
    self.Groups = componentDef(compName = 'Group', compDelete=True, itemsKeep=() ) 	#itemsKeep=('GroupName1', 'GroupName2', ...)
    self.Policies = componentDef(compName = 'Policy', compDelete=True, itemsKeep=() )
    self.Roles = componentDef(compName = 'Role', compDelete=True, itemsKeep=() )
    self.InstanceProfiles = componentDef(compName = 'Instance Profile', compDelete=True, itemsKeep=() )
