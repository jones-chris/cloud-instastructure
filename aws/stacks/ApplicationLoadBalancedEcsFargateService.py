from aws_cdk import (
    core,
    aws_iam,
    aws_ecs_patterns,
    aws_elasticloadbalancingv2,
    aws_ec2,
    aws_ecs
)


class ApplicationLoadBalancedEcsFargateService:

    def __init__(self, scope: core.Construct, id: str, docker_image_name: str, container_port: int, container_cpu: int,
                 container_memory_limit_mib: int, desired_container_count: int, vpc: aws_ec2.Vpc = None, **kwargs):

        super().__init__(scope, id, **kwargs)

        # Set Defaults if not in parameters.
        if vpc is None:
            vpc = aws_ec2.Vpc(
                self, 'Vpc'
            )

        # Execution and task role
        self.role = aws_iam.Role(
            self, 'TaskDefinitionExecutionRole',
            assumed_by=aws_iam.ServicePrincipal(service='ecs-tasks.amazonaws.com'),
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
                                'ec2:CreateNetworkInterface',
                                'ec2:DescribeNetworkInterfaces',
                                'ec2:DeleteNetworkInterface',
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
                    aws_iam.ServicePrincipal('ecs.amazonaws.com')
                ]
            )
        )

        # Applicaiton Load Balanced Fargate service
        self.application_load_balanced_fargate_service = aws_ecs_patterns.ApplicationLoadBalancedFargateService(
            self, 'LoadBalancedFargateService',
            assign_public_ip=False,
            cpu=container_cpu,
            memory_limit_mib=container_memory_limit_mib,
            task_image_options=aws_ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                container_port=container_port,
                enable_logging=True,
                execution_role=self.role,
                task_role=self.role,
                image=aws_ecs.RepositoryImage(
                    image_name=docker_image_name
                ),
            ),
            desired_count=desired_container_count,
            listener_port=80,
            protocol=aws_elasticloadbalancingv2.ApplicationProtocol.HTTP,
            public_load_balancer=True,
            vpc=vpc
        )
