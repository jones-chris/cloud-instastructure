from typing import Sequence

from aws_cdk import (
    core,
    aws_iam,
    aws_elasticloadbalancingv2,
    aws_ec2,
    aws_ecs,
    aws_apigateway, aws_lambda)

from common import Utils


class ApiGatewayProxyNetworkLoadBalancedEcsFargateService(core.Construct):

    def __init__(self, scope: core.Construct, id: str, stack_name: str, task_definition_cpu: int, task_definition_memory_limit_mib: int,
                 docker_image_name: str, container_port: int, desired_container_count: int, private_subnets: Sequence[aws_ec2.Subnet] = None,
                 public_subnets: Sequence[aws_ec2.Subnet] = None, private_security_group: aws_ec2.SecurityGroup = None,
                 public_security_group: aws_ec2.SecurityGroup = None, vpc: aws_ec2.Vpc = None, fargate_cluster: aws_ecs.Cluster = None,
                 authorizer_lambda_arn: str = None, authorizer_lambda_role_arn: str = None, **kwargs):
        super().__init__(scope, id, **kwargs)

        # Role
        self.role = aws_iam.Role(
            self, 'Role',
            assumed_by=aws_iam.ServicePrincipal(service='ecs.amazonaws.com'),
            managed_policies=[
                aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                    managed_policy_name='service-role/AmazonECSTaskExecutionRolePolicy'
                )
            ],
            inline_policies={
                id: aws_iam.PolicyDocument(
                    statements=[
                        aws_iam.PolicyStatement(
                            effect=aws_iam.Effect.ALLOW,
                            actions=[
                                'kms:Encrypt',
                                'kms:Decrypt',
                                'kms:ReEncrypt*',
                                'kms:GenerateDataKey*',
                                'kms:DescribeKey',
                                'ec2:CreateNetworkInterface',
                                'ec2:DescribeNetworkInterfaces',
                                'ec2:DeleteNetworkInterface',
                                # Remaining actions from https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-ecs.html
                                'elasticloadbalancing:DeregisterInstancesFromLoadBalancer',
                                'elasticloadbalancing:DeregisterTargets',
                                'elasticloadbalancing:Describe*',
                                'elasticloadbalancing:RegisterInstancesWithLoadBalancer',
                                'elasticloadbalancing:RegisterTargets',
                                'ec2:Describe*',
                                'ec2:AuthorizeSecurityGroupIngress'
                            ],
                            resources=[
                                '*'
                            ]
                        )
                    ]
                )
            }
        )
        self.role.assume_role_policy.add_statements(
            aws_iam.PolicyStatement(
                actions=[
                    'sts:AssumeRole'
                ],
                principals=[
                    aws_iam.ServicePrincipal(service='ecs-tasks.amazonaws.com')
                ]
            )
        )

        # Set Defaults if parameters are None
        if vpc is None:
            vpc = aws_ec2.Vpc(
                self, 'Vpc'
            )

        if private_subnets is None:
            private_subnets = vpc.private_subnets

        if public_subnets is None:
            public_subnets = vpc.public_subnets

        if public_security_group is None:
            public_security_group = aws_ec2.SecurityGroup(
                self, 'PublicSecurityGroup',
                vpc=vpc,
                allow_all_outbound=True
            )
            # Allow inbound HTTP traffic
            public_security_group.add_ingress_rule(
                peer=aws_ec2.Peer.ipv4(cidr_ip='0.0.0.0/0'),
                connection=aws_ec2.Port.tcp(port=80)
            )
            # Allow inbound HTTPS traffic
            public_security_group.add_ingress_rule(
                peer=aws_ec2.Peer.ipv4(cidr_ip='0.0.0.0/0'),
                connection=aws_ec2.Port.tcp(port=443)
            )

        if private_security_group is None:
            private_security_group = aws_ec2.SecurityGroup(
                self, 'PrivateSecurityGroup',
                vpc=vpc,
                allow_all_outbound=True
            )

            public_subnet_cidr_blocks = Utils.get_subnet_cidr_blocks(public_subnets)

            # Create an ingress rule for each of the NLB's subnet's CIDR ranges and add the rules to the ECS service's
            # security group.  This will allow requests from the NLB to go into the ECS service.  This allow inbound
            # traffic from public subnets.
            for cidr_block in public_subnet_cidr_blocks:
                private_security_group.add_ingress_rule(
                    peer=aws_ec2.Peer.ipv4(cidr_ip=cidr_block),
                    connection=aws_ec2.Port.tcp(port=container_port)
                )

        if fargate_cluster is None:
            fargate_cluster = aws_ecs.Cluster(
                self, 'FargateCluster',
            )

        task_def = aws_ecs.FargateTaskDefinition(
            self, 'TaskDefinition',
            cpu=task_definition_cpu,
            memory_limit_mib=task_definition_memory_limit_mib,
            task_role=self.role,
            execution_role=self.role
        )

        container = aws_ecs.ContainerDefinition(
            self, 'Container',
            image=aws_ecs.ContainerImage.from_registry(
                name=docker_image_name
            ),
            task_definition=task_def,
            logging=aws_ecs.AwsLogDriver(
                stream_prefix='/ecs'
            )
        )
        container.add_port_mappings(
            aws_ecs.PortMapping(
                container_port=container_port,
                protocol=aws_ec2.Protocol.TCP
            )
        )

        ecs_service = aws_ecs.FargateService(
            self, 'FargateService',
            cluster=fargate_cluster,
            task_definition=task_def,
            vpc_subnets=aws_ec2.SubnetSelection(
                subnets=private_subnets
            ),
            security_group=private_security_group,
            desired_count=desired_container_count
        )

        target_group = aws_elasticloadbalancingv2.NetworkTargetGroup(
            self, 'TargetGroup',
            port=80,  # Health check occurs over HTTP
            health_check=aws_elasticloadbalancingv2.HealthCheck(
                protocol=aws_elasticloadbalancingv2.Protocol.TCP
            ),
            targets=[
                ecs_service
            ],
            vpc=vpc
        )

        nlb = aws_elasticloadbalancingv2.NetworkLoadBalancer(
            self, 'NetworkLoadBalancer',
            vpc=vpc,
            internet_facing=False,
            vpc_subnets=aws_ec2.SubnetSelection(
                subnets=public_subnets
            ),
        )
        nlb.add_listener(
            id='Listener',
            port=80,  # HTTP listener
            default_target_groups=[
                target_group
            ]
        )

        # nlb.log_access_logs(  # todo:  add this later when you have time to research the correct bucket policy.
        #     bucket=aws_s3.Bucket(
        #         self, 'LoadBalancerLogBucket',
        #         bucket_name='load-balancer-logs',
        #         public_read_access=False,
        #         block_public_access=aws_s3.BlockPublicAccess(
        #             block_public_policy=True,
        #             restrict_public_buckets=True
        #         )
        #     )
        # )

        # Dependencies
        ecs_service.node.add_dependency(nlb)

        # API Gateway
        rest_api = aws_apigateway.RestApi(
            self, stack_name
        )
        resource = rest_api.root.add_resource(
            path_part='{proxy+}',
            default_method_options=aws_apigateway.MethodOptions(
                request_parameters={
                    'method.request.path.proxy': True
                }
            )
        )

        token_authorizer = None
        if authorizer_lambda_arn and authorizer_lambda_role_arn:
            token_authorizer = aws_apigateway.TokenAuthorizer(  #todo: make this a parameter?
                self, 'JwtTokenAuthorizer',
                results_cache_ttl=core.Duration.minutes(5),
                identity_source='method.request.header.Authorization',
                assume_role=aws_iam.Role.from_role_arn(
                    self, 'AuthorizerLambdaInvokationRole',
                    role_arn=authorizer_lambda_role_arn
                ),
                handler=aws_lambda.Function.from_function_arn(
                    self, 'AuthorizerLambda',
                    function_arn=authorizer_lambda_arn
                )
            )

        resource.add_method(
            http_method='ANY',
            authorization_type=aws_apigateway.AuthorizationType.CUSTOM,
            authorizer=token_authorizer,
            integration=aws_apigateway.HttpIntegration(
                url=f'http://{nlb.load_balancer_dns_name}/{{proxy}}',
                http_method='ANY',
                proxy=True,
                options=aws_apigateway.IntegrationOptions(
                    request_parameters={
                        'integration.request.path.proxy': 'method.request.path.proxy'
                    },
                    connection_type=aws_apigateway.ConnectionType.VPC_LINK,
                    vpc_link=aws_apigateway.VpcLink(
                        self, 'VpcLink',
                        description=f'API Gateway VPC Link to internal NLB for {stack_name}',
                        vpc_link_name=stack_name,
                        targets=[
                            nlb
                        ]
                    )
                )
            )
        )
