from typing import Sequence

import boto3
from aws_cdk import (
    core,
    aws_ec2
)

from common.ExistingSubnet import ExistingSubnet


# def create_aws_subnets(existing_subnets: Sequence[ExistingSubnet], scope: core.Construct, ) -> list[aws_ec2.ISubnet]:
#     aws_subnets = []
#     for existing_subnet in existing_subnets:
#         aws_subnets.append(
#             aws_ec2.Subnet.from_subnet_attributes(
#                 scope=scope, id=existing_subnet.subnet_id,
#                 subnet_id=existing_subnet.subnet_id,
#                 availability_zone=existing_subnet.availability_zone
#             )
#         )
#
#     return aws_subnets

def get_subnet_cidr_blocks(subnets: Sequence[aws_ec2.Subnet]) -> list(str):
    subnet_descriptions = boto3.client('ec2').describe_subnets(
        SubnetIds=[subnet.subnet_id for subnet in subnets]
    )['Subnets']

    return [subnet['CidrBlock'] for subnet in subnet_descriptions]
