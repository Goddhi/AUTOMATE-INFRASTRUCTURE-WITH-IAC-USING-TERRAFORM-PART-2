# AUTOMATE INFRASTRUCTURE WITH IAC USING TERRAFORM PART 2

### Table of Contents

[Introduction](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#introduction)

[Prerequisites](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#prerequisites)

[Networking](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#networking)

[Creating our Private Subnets](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#creating-our-private-subnets)

[Introducing Tagging](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#introducing-tagging)

[Creating our Internet Gateway](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#creating-our-internet-gateway)

[Creating our NAT Gateway](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#creating-our-nat-gateways)

[AWS Routes](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#aws-routes)

[Creating Private routes](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#creating-private-routes)

[Creating Public routes](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#creating-public-routes)

[AWS Identity and Access Management](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#aws-identity-and-access-management)

[Creating an IAM Role (AssumeRole)](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#creating-an-iam-role-assumerole)

[Creating an IAM Policy](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#creating-an-iam-policy)

[CREATE SECURITY GROUPS](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#create-security-groups)

[Create a Certificate from Amazon Certificate Manager](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#create-a-certificate-from-amazon-certificate-manager)

[Create an external (Internet facing) Application Load Balancer (ALB)](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#create-an-external-internet-facing-application-load-balancer-alb)

[Create an Internal (Internal) Application Load Balancer (ALB)](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#create-an-internal-internal-application-load-balancer-alb)

[CREATING AUTOSCALING GROUPS](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#creating-autoscaling-groups)

[Creating notifications for all the auto-scaling groups](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#creating-notifications-for-all-the-auto-scaling-groups)

[Creating our Launch Templates](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#creating-our-launch-templates)

[Provisioning Storage and Database](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#provisioning-storage-and-database)

[Creating an EFS file system](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#creating-an-efs-file-system)

[Creating an RDS instance](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#creating-an-rds-instance)

[Conclusion](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-2#conclusion)

[Project Source Code](https://github.com/Goddhi/terraform-source-code)
Additional Tasks

### Introduction

This is the second part of the series on Infrastructure as Code using Terraform. In this part, we will be creating a VPC, Subnets, Internet Gateway, NAT gateway, Route Table, AutoScaling group, RDS, Security Group and EC2 instance. We\ will also be using the outputs from the previous part to create the VPC and Subnets. To get up to speed with the previous part, you can read it [here](https://github.com/Goddhi/AUTOMATE-INFRASTRUCTURE-WITH-IAC-USING-TERRAFORM-PART-1)

Note: We are building according to this architecture

![architecture img](Images/resource-architecture.png)

### Prerequisites

- [Terraform](https://www.terraform.io/downloads.html)
- [AWS Account](https://aws.amazon.com/)
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html)
- [Project code] (https://github.com/manny-uncharted/Terraform-codes)


### Networking

As a continuation to our previous part we would get started by

- Initializing Terraform

```
terraform init
```

### Creating our Private Subnets

We would need to create 4 private subnets in our VPC.

    - In the ```main.tf``` file, we would create a resource for the private subnets

```
resource "aws_subnet" "private" {
  count                   = var.preferred_number_of_private_subnets == null ? length(data.aws_availability_zones.available.names) : var.preferred_number_of_public_subnets
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index + 2)
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[count.index]
}
```
    - In our ```variables.tf``` file, we would add the following variables

```
variable "preferred_number_of_private_subnets" {
  # default = 4
  type        = number
  description = "Number of private subnets to create. If not specified, all available AZs will be used."
}
```
    - In our 'terraform.tfvars' file, we would add the following

```
preferred_number_of_private_subnets = 4
```
    - We would then run terraform plan to see the changes that would be made

```
terraform plan
```
### Introducing Tagging
We would need to tag our resources to make it easier to identify them.
    - We would need to add the following to our main.tf file to the public and private subnets

```
tags = merge(
    var.tags,
    {
      Name = format("%s-Private-subnet-%s", var.name, count.index + 1)
    },
)
```
    - In our variables.tf file, we would add the following variables

```
variable "tags" {
  type        = map(string)
  description = "A map of tags to add to all resources."
  default     = {}
}
```
Note: The merge function is used to ```merge``` two maps together. In this case, we are merging the ```var.tags``` and the ```Name``` tag. The ```var.tags``` is a map of tags that we would pass in as a variable. The ```Name``` tag is the name of the subnet. The 'format' function is used to format the string. In this case, we are formatting the string to include our defined name, the type of subnet and the index of the subnet.

    - Let's run 'terraform plan' to see the changes that would be made

```
terraform plan
```
### Creating our Internet Gateway
We would need to create an internet gateway to allow our instances to access the internet.
    - Create an internet gateway in a separate file called internet_gateway.tf

```
resource "aws_internet_gateway" "ig" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    var.tags,
    {
      Name = format("%s-Internet-Gateway", aws_vpc.main.id, "Internet-Gateway")
    },
  )
}
```
    - Run terraform plan to see the changes that would be made

```
terraform plan
```
### Creating our NAT Gateways

We would need to create a NAT gateway to allow our instances to access the internet without exposing them to the public internet. For the NAT gateway, we would need an elastic IP address.

    - Create an elastic IP address in a separate file called ```nat_gateway.tf```

```
resource "aws_eip" "nat_eip" {
  vpc        = true
  depends_on = [aws_internet_gateway.ig]

  tags = merge(
    var.tags,
    {
      Name = format("%s-EIP-%s", var.name, var.environment)
    },
  )
}
```
Note: The depends_on is used to ensure that the elastic IP address is created after the internet gateway is created. This ensures that the elastic IP address does not get created before the internet gateway.

- Let's now move on to creating the NAT gateway

```
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = element(aws_subnet.public.*.id, 0)
  depends_on    = [aws_internet_gateway.ig]

  tags = merge(
    var.tags,
    {
      Name = format("%s-Nat-%s", var.name, var.environment)
    },
  )
}
```
Note: Don't forget to declare the variable ```environment``` in the ```variables.tf``` file. As this would help us identify the environment we are deploying to.

```
variable "environment" {
  type        = string
  description = "The environment we are deploying to."
  default     = "dev"
}
```
- Let's run terraform plan to see the changes that would be made

```
terraform validate
terraform plan
```
Note: The ```terraform validate``` command is used to validate the syntax of the terraform files. It is a good practice to run this command before running ```terraform plan``` to ensure that there are no syntax errors in the terraform files.

### AWS Routes

We need to create two route tables for our VPC. One for the public subnets and the other for the private subnets. For the private subnets, we would add the NAT gateway as that would stand as our gateway for the private subnets. For the public subnets, we would add the internet gateway as that would stand as our gateway for the public subnets. We would be doing the following:

- Creating the private routes
- Creating the public routes

#### Creating Private routes

- Create a file called routes.tf and add the following to it to create the private route table

```
resource "aws_route_table" "private-rtb" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    var.tags,
    {
      Name = format("%s-PrivateRoute-Table-%s", var.name, var.environment)
    },
  )
}
```
Let's now create the private route table and attach a nat gateway to it.

```
# Create route for the private route table and attach a nat gateway to it
resource "aws_route" "private-rtb-route" {
  route_table_id         = aws_route_table.private-rtb.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_nat_gateway.nat.id
}
```
- We need to associate all the private subnets to the private route table.

```
# associate all private subnets with the private route table
resource "aws_route_table_association" "private-subnets-assoc" {
  count          = length(aws_subnet.private[*].id)
  subnet_id      = element(aws_subnet.private[*].id, count.index)
  route_table_id = aws_route_table.private-rtb.id
}
```
#### Creating Public routes

Now let's move on to creating our public routes which would then be associated to the internet gateway and then associate our public subnets to the public route table.

    - Add the following line to ```routes.tf``` to create the public route table

```
resource "aws_route_table" "public-rtb" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    var.tags,
    {
      Name = format("%s-PublicRoute-Table-%s", var.name, var.environment)
    },
  )
}
```
- Let's now create the public route table and attach an internet gateway to it.

```
# Create route for the public route table and attach a internet gateway to it
resource "aws_route" "public-rtb-route" {
  route_table_id         = aws_route_table.public-rtb.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.ig.id
}
```
- Let's now associate our public subnets with the public route table.

```
# associate all public subnets with the public route table
resource "aws_route_table_association" "public-subnets-assoc" {
  count          = length(aws_subnet.public[*].id)
  subnet_id      = element(aws_subnet.public[*].id, count.index)
  route_table_id = aws_route_table.public-rtb.id
}
```
- Let's run terraform plan to see the changes that would be made

```
terraform validate
terraform plan
```
    
- Let's now run terraform apply to apply the changes

```
terraform apply --auto-approve
```
### AWS Identity and Access Management

We want to pass an IAM role on our EC2 instances to give them access to some specific resources, so we need to do the following:

### Creating an IAM role (AssumeRole)

Assume Role uses Security Token Service (STS) API that returns a set of temporary security credentials that you can use to access AWS resources that you might not normally have access to. These temporary credentials consist of an access key ID, a secret access key, and a security token. Typically, you use AssumeRole within your account or for cross-account access.

Let's create a file called ```roles.tf``` and add the following to it to create an IAM role

```resource "aws_iam_role" "ec2_instance_role" {
name = "ec2_instance_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = merge(
    var.tags,
    {
      Name = "aws assume role"
    },
  )
}
```
Note: This role grants an entity which is ec2, the ability to assume the role.

### Creating an IAM policy

This is where we need to define a required policy (i.e., permissions) according to our requirements. For example, allowing an IAM role to perform the action describe applied to EC2 instances:

```
resource "aws_iam_policy" "policy" {
  name        = "ec2_instance_policy"
  description = "A test policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]

  })

  tags = merge(
    var.tags,
    {
      Name =  "aws assume policy"
    },
  )

}
```
- Let's attach the Policy to the IAM Role. We can do this by adding the following to ```roles.tf```

```
resource "aws_iam_role_policy_attachment" "test-attach" {
        role       = aws_iam_role.ec2_instance_role.name
        policy_arn = aws_iam_policy.policy.arn
    }
```
Let's create an instance profile and interpolate the ```IAM Role``` to it. We can do this by adding the following to ```roles.tf```

```
resource "aws_iam_instance_profile" "ip" {
        name = "aws_instance_profile_test"
        role =  aws_iam_role.ec2_instance_role.name
    }
```

Note: An instance profile is a container for an IAM role that you can use to pass role information to an Amazon EC2 instance when the instance starts.

We are pretty much done with Identity and Management part for now, let us move on and create other resources required.

### CREATE SECURITY GROUPS

Security groups are stateful, which means that if you allow inbound traffic to a resource, the same outbound traffic is automatically allowed, and vice versa. For example, if you allow inbound HTTP traffic, any outbound HTTP traffic is automatically allowed, and vice versa. We are going to create all the security groups in a single file, then we are going to reference this security group within each resource that needs it.

- Create a file called security.tf and add the following to it:

```
# security group for alb, to allow acess from any where for HTTP and HTTPS traffic
resource "aws_security_group" "ext-alb-sg" {
  name        = "ext-alb-sg"
  vpc_id      = aws_vpc.main.id
  description = "Allow TLS inbound traffic"

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

 tags = merge(
    var.tags,
    {
      Name = "ext-alb-sg"
    },
  )

}

# security group for bastion, to allow access into the bastion host from you IP
resource "aws_security_group" "bastion_sg" {
  name        = "vpc_web_sg"
  vpc_id = aws_vpc.main.id
  description = "Allow incoming HTTP connections."

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

   tags = merge(
    var.tags,
    {
      Name = "Bastion-SG"
    },
  )
}

#security group for nginx reverse proxy, to allow access only from the extaernal load balancer and bastion instance
resource "aws_security_group" "nginx-sg" {
  name   = "nginx-sg"
  vpc_id = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

   tags = merge(
    var.tags,
    {
      Name = "nginx-SG"
    },
  )
}

resource "aws_security_group_rule" "inbound-nginx-http" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ext-alb-sg.id
  security_group_id        = aws_security_group.nginx-sg.id
}

resource "aws_security_group_rule" "inbound-bastion-ssh" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.bastion_sg.id
  security_group_id        = aws_security_group.nginx-sg.id
}

# security group for ialb, to have acces only from nginx reverser proxy server
resource "aws_security_group" "int-alb-sg" {
  name   = "my-alb-sg"
  vpc_id = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.tags,
    {
      Name = "int-alb-sg"
    },
  )

}

resource "aws_security_group_rule" "inbound-ialb-https" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.nginx-sg.id
  security_group_id        = aws_security_group.int-alb-sg.id
}

# security group for webservers, to have access only from the internal load balancer and bastion instance
resource "aws_security_group" "webserver-sg" {
  name   = "my-asg-sg"
  vpc_id = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.tags,
    {
      Name = "webserver-sg"
    },
  )

}

resource "aws_security_group_rule" "inbound-web-https" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.int-alb-sg.id
  security_group_id        = aws_security_group.webserver-sg.id
}

resource "aws_security_group_rule" "inbound-web-ssh" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.bastion_sg.id
  security_group_id        = aws_security_group.webserver-sg.id
}

# security group for datalayer to alow traffic from websever on nfs and mysql port and bastiopn host on mysql port
resource "aws_security_group" "datalayer-sg" {
  name   = "datalayer-sg"
  vpc_id = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

 tags = merge(
    var.tags,
    {
      Name = "datalayer-sg"
    },
  )
}

resource "aws_security_group_rule" "inbound-nfs-port" {
  type                     = "ingress"
  from_port                = 2049
  to_port                  = 2049
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.webserver-sg.id
  security_group_id        = aws_security_group.datalayer-sg.id
}

resource "aws_security_group_rule" "inbound-mysql-bastion" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.bastion_sg.id
  security_group_id        = aws_security_group.datalayer-sg.id
}

resource "aws_security_group_rule" "inbound-mysql-webserver" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.webserver-sg.id
  security_group_id        = aws_security_group.datalayer-sg.id
}
```

Note: The ```aws_security_group_rule``` resources are used to allow traffic between security groups.

### Create a Certificate from Amazon Certificate Manager
- Create cert.tf file and add the following code snippets to it.
```
# The entire section create a certiface, public zone, and validate the certificate using DNS method

# Create the certificate using a wildcard for all the domains created in drexii.online
resource "aws_acm_certificate" "drexii" {
  domain_name       = "*.drexii.online"
  validation_method = "DNS"
}

# calling the hosted zone
data "aws_route53_zone" "drexii" {
  name         = "drexii.online"
  private_zone = false
}

# selecting validation method
resource "aws_route53_record" "drexii" {
  for_each = {
    for dvo in aws_acm_certificate.drexii.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.drexii.zone_id
}

# validate the certificate through DNS method
resource "aws_acm_certificate_validation" "drexii" {
  certificate_arn         = aws_acm_certificate.drexii.arn
  validation_record_fqdns = [for record in aws_route53_record.drexii : record.fqdn]
}

# create records for tooling
resource "aws_route53_record" "tooling" {
  zone_id = data.aws_route53_zone.drexii.zone_id
  name    = "tooling.drexii.online"
  type    = "A"

  alias {
    name                   = aws_lb.ext-alb.dns_name
    zone_id                = aws_lb.ext-alb.zone_id
    evaluate_target_health = true
  }
}

# create records for wordpress
resource "aws_route53_record" "wordpress" {
  zone_id = data.aws_route53_zone.drexii.zone_id
  name    = "wordpress.drexii.online"
  type    = "A"

  alias {
    name                   = aws_lb.ext-alb.dns_name
    zone_id                = aws_lb.ext-alb.zone_id
    evaluate_target_health = true
  }
}
```
### Create an external (Internet facing) Application Load Balancer (ALB)

First of all, we will create the ALB, then we create the target group and lastly we will create the listener rule.

- We need to create an ALB to balance the traffic between the instances. Create a file called alb.tf and add the following code snippets to it.

```
# Create external application load balancer.
resource "aws_lb" "ext-alb" {
  name     = "ext-alb"
  internal = false
  security_groups = [
    aws_security_group.ext-alb-sg.id,
  ]

  subnets = [
    aws_subnet.public[0].id,
    aws_subnet.public[1].id
  ]

  tags = merge(
    var.tags,
    {
      Name = "ACS-ext-alb"
    },
  )

  ip_address_type    = "ipv4"
  load_balancer_type = "application"
}
```
- To inform our ALB where to route the traffic we need to create a target group to point to its targets:

```
# Create target group to point to its targets.
resource "aws_lb_target_group" "nginx_tg" {
  health_check {
    interval            = 10
    path                = "/healthstatus"
    protocol            = "HTTPS"
    timeout             = 5
    healthy_threshold   = 5
    unhealthy_threshold = 2
  }
  name        = format("%s-nginx-tg-%s", var.name, var.environment)
  port        = 443
  protocol    = "HTTPS"
  target_type = "instance"
  vpc_id      = aws_vpc.main.id
}
```
- We need to create a listener rule to route the traffic to the target group.

```

# Create listener to redirect traffic to the target group.
resource "aws_lb_listener" "nginx-listener" {
  load_balancer_arn = aws_lb.ext-alb.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate_validation.drexii.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.nginx-tg.arn
  }
}
```
### Create an Internal (Internal) Application Load Balancer (ALB)

For the internal ALB, we will follow the same concepts as the external load balancer. This load balancer would be used to balance the traffic between the instances in the private subnet which is our webservers.

- Create an internal load balancer with this code snippet:

```
resource "aws_lb" "int-alb" {
  name     = "ialb"
  internal = true
  security_groups = [
    aws_security_group.int-alb-sg.id,
  ]

  subnets = [
    aws_subnet.private[0].id,
    aws_subnet.private[1].id
  ]

  tags = merge(
    var.tags,
    {
      Name = format("%s-int-alb-%s", var.name, var.environment)
    },
  )

  ip_address_type    = "ipv4"
  load_balancer_type = "application"
}
```
- To inform our ALB where to route the traffic we need to create a target group to point to its targets:

```# Create target group for wordpress
resource "aws_lb_target_group" "wordpress-tg" {
  health_check {
    interval            = 10
    path                = "/healthstatus"
    protocol            = "HTTPS"
    timeout             = 5
    healthy_threshold   = 5
    unhealthy_threshold = 2
  }

  name        = format("%s-wordpress-tg-%s", var.name, var.environment)
  port        = 443
  protocol    = "HTTPS"
  target_type = "instance"
  vpc_id      = aws_vpc.main.id
}

# --- target group for tooling -------

resource "aws_lb_target_group" "tooling-tg" {
  health_check {
    interval            = 10
    path                = "/healthstatus"
    protocol            = "HTTPS"
    timeout             = 5
    healthy_threshold   = 5
    unhealthy_threshold = 2
  }

  name        = format("%s-tooling-tg-%s", var.name, var.environment)
  port        = 443
  protocol    = "HTTPS"
  target_type = "instance"
  vpc_id      = aws_vpc.main.id
}
```
- We need to create a listener rule to route the traffic to the target group.

# For this aspect a single listener was created for the wordpress which is default,
# A rule was created to route traffic to tooling when the host header changes

resource "aws_lb_listener" "web-listener" {
  load_balancer_arn = aws_lb.int-alb.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate_validation.drexii.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wordpress-tg.arn
  }
}

###   listener rule for tooling target

resource "aws_lb_listener_rule" "tooling-listener" {
  listener_arn = aws_lb_listener.web-listener.arn
  priority     = 99

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tooling-tg.arn
  }

  condition {
    host_header {
      values = ["tooling.drexii.online"]
    }
  }
}

- Now run terraform plan and terraform apply to create the load balancers.

```
terraform plan
terraform apply
```

### CREATING AUTOSCALING GROUPS.

n this section, we will create the Auto Scaling Group (ASG) we need for the architecture. Our ASG needs to be able to scale the EC2s out and in depending on the application traffic.

Before we start configuring an ASG, we need to create the launch template and the AMI needed. For now, we are going to use a random AMI from AWS, then in project 19, we will use Packer to create our AMI.

Based on our architecture we need Auto Scaling Groups for bastion, Nginx, wordpress and tooling, so we will create two files; asg-bastion-nginx.tf will contain Launch Template and Austoscaling group for Bastion and Nginx, then asg-wordpress-tooling.tf will contain Launch Template and Autoscaling group for wordpress and tooling.

### Creating notifications for all the auto-scaling groups

Create ```asg-bastion-nginx.tf``` file and add the following code snippet:

```
## creating sns topic for all the auto scaling groups
resource "aws_sns_topic" "manny-sns" {
name = "Default_CloudWatch_Alarms_Topic"
}
```
- Create notifications for all the auto-scaling groups

```
resource "aws_autoscaling_notification" "david_notifications" {
  group_names = [
    aws_autoscaling_group.bastion-asg.name,
    aws_autoscaling_group.nginx-asg.name,
    aws_autoscaling_group.wordpress-asg.name,
    aws_autoscaling_group.tooling-asg.name,
  ]
  notifications = [
    "autoscaling:EC2_INSTANCE_LAUNCH",
    "autoscaling:EC2_INSTANCE_TERMINATE",
    "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
    "autoscaling:EC2_INSTANCE_TERMINATE_ERROR",
  ]

  topic_arn = aws_sns_topic.david-sns.arn
}
```

### Creating our Launch Templates
- In our asg-bastion-nginx.tf file, we will create our launch templates for the bastion instance.

```
# Get the list of availability zones
resource "random_shuffle" "az_list" {
  input        = data.aws_availability_zones.available.names
}


# Launch template for bastion hosts
resource "aws_launch_template" "bastion-launch-template" {
  image_id               = var.ami
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.bastion_sg.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.ip.id
  }

  key_name = var.keypair

  placement {
    availability_zone = "${random_shuffle.az_list.result}"
  }

  lifecycle {
    create_before_destroy = true
  }

  tag_specifications {
    resource_type = "instance"

   tags = merge(
    var.tags,
    {
      Name = format("%s-bastion-launch-template-%s", var.name, var.environment)
    },
  )
  }

  user_data = filebase64("${path.module}/bastion.sh")
}


# ---- Autoscaling for bastion  hosts
resource "aws_autoscaling_group" "bastion-asg" {
  name                      = "bastion-asg"
  max_size                  = 2
  min_size                  = 2
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 2

  vpc_zone_identifier = [
    aws_subnet.public[0].id,
    aws_subnet.public[1].id
  ]

  launch_template {
    id      = aws_launch_template.bastion-launch-template.id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = format("%s-bastion-asg-%s", var.name, var.environment)
    propagate_at_launch = true
  }

}


# launch template for nginx
resource "aws_launch_template" "nginx-launch-template" {
  image_id               = var.ami
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.nginx-sg.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.ip.id
  }

  key_name =  var.keypair

  placement {
    availability_zone = "random_shuffle.az_list.result"
  }

  lifecycle {
    create_before_destroy = true
  }

  tag_specifications {
    resource_type = "instance"

    tags = merge(
    var.tags,
    {
      Name = format("%s-nginx-launch-template-%s", var.name, var.environment)
    },
  )
  }

  user_data = filebase64("${path.module}/nginx.sh")
}

# ------ Autoscslaling group for reverse proxy nginx ---------

resource "aws_autoscaling_group" "nginx-asg" {
  name                      = "nginx-asg"
  max_size                  = 2
  min_size                  = 1
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 1

  vpc_zone_identifier = [
    aws_subnet.public[0].id,
    aws_subnet.public[1].id
  ]

  launch_template {
    id      = aws_launch_template.nginx-launch-template.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = format("%s-nginx-asg-%s", var.name, var.environment)
    propagate_at_launch = true
  }

}

# attaching autoscaling group of nginx to external load balancer
resource "aws_autoscaling_attachment" "asg_attachment_nginx" {
  autoscaling_group_name = aws_autoscaling_group.nginx-asg.id
  alb_target_group_arn   = aws_lb_target_group.nginx-tg.arn
}
```
- Let's move on with creating and auto-scaling group for Wordpress and tooling. Create asg-wordpress-tooling.tf file and add the following code snippet:

```
# launch template for wordpress

resource "aws_launch_template" "wordpress-launch-template" {
  image_id               = var.ami
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.webserver-sg.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.ip.id
  }

  key_name = var.keypair

  placement {
    availability_zone = "random_shuffle.az_list.result"
  }

  lifecycle {
    create_before_destroy = true
  }

  tag_specifications {
    resource_type = "instance"

    tags = merge(
    var.tags,
    {
      Name = format("%s-wordpress-launch-template-%s", var.name, var.environment)
    },
  )

  }

  user_data = filebase64("${path.module}/wordpress.sh")
}

# ---- Autoscaling for wordpress application

resource "aws_autoscaling_group" "wordpress-asg" {
  name                      = "wordpress-asg"
  max_size                  = 2
  min_size                  = 1
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 1
  vpc_zone_identifier = [

    aws_subnet.private[0].id,
    aws_subnet.private[1].id
  ]

  launch_template {
    id      = aws_launch_template.wordpress-launch-template.id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = format("%s-wordpress-asg-%s", var.name, var.environment)
    propagate_at_launch = true
  }
}

# attaching autoscaling group of  wordpress application to internal loadbalancer
resource "aws_autoscaling_attachment" "asg_attachment_wordpress" {
  autoscaling_group_name = aws_autoscaling_group.wordpress-asg.id
  alb_target_group_arn   = aws_lb_target_group.wordpress-tg.arn
}

# launch template for toooling
resource "aws_launch_template" "tooling-launch-template" {
  image_id               = var.ami
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.webserver-sg.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.ip.id
  }

  key_name = var.keypair

  placement {
    availability_zone = "random_shuffle.az_list.result"
  }

  lifecycle {
    create_before_destroy = true
  }

  tag_specifications {
    resource_type = "instance"

  tags = merge(
    var.tags,
    {
      Name = format("%s-tooling-launch-template-%s", var.name, var.environment)
    },
  )

  }

  user_data = filebase64("${path.module}/tooling.sh")
}

# ---- Autoscaling for tooling -----

resource "aws_autoscaling_group" "tooling-asg" {
  name                      = "tooling-asg"
  max_size                  = 2
  min_size                  = 1
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 1

  vpc_zone_identifier = [

    aws_subnet.private[0].id,
    aws_subnet.private[1].id
  ]

  launch_template {
    id      = aws_launch_template.tooling-launch-template.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "tooling-launch-template"
    propagate_at_launch = true
  }
}
# attaching autoscaling group of  tooling application to internal loadbalancer
resource "aws_autoscaling_attachment" "asg_attachment_tooling" {
  autoscaling_group_name = aws_autoscaling_group.tooling-asg.id
  alb_target_group_arn   = aws_lb_target_group.tooling-tg.arn
}
```
Note: Remember to declare your variables in variables.tf file. And also for the wordpress.sh and tooling.sh files. You can find the code for these files in the files directory of this repository.

### Provisioning Storage and Database

The goal of this section is to create storage and a database for the WordPress application. We will be using AWS RDS for the database and AWS EFS for the storage.

### Creating an EFS file system

To create an EFS you need to create a KMS key.

AWS Key Management Service (KMS) makes it easy for you to create and manage cryptographic keys and control their use across a wide range of AWS services and in your applications.

Create a efs.tf file and add the following code snippet:
```
# create key from key management system
resource "aws_kms_key" "ACS-kms" {
  description = "KMS key "
  policy      = <<EOF
  {
  "Version": "2012-10-17",
  "Id": "kms-key-policy",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::${var.account_no}:user/Terraform" },
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}
EOF
}

# create key alias
resource "aws_kms_alias" "alias" {
  name          = "alias/kms"
  target_key_id = aws_kms_key.ACS-kms.key_id
}
```
- Let us create EFS and its mount targets- add the following code to efs.tf

```
# create Elastic file system
resource "aws_efs_file_system" "ACS-efs" {
  encrypted  = true
  kms_key_id = aws_kms_key.ACS-kms.arn

  tags = merge(
    var.tags,
    {
      Name = format("%s-efs-%s", var.name, var.environment)
    },
  )
}

# set first mount target for the EFS 
resource "aws_efs_mount_target" "subnet-1" {
  file_system_id  = aws_efs_file_system.ACS-efs.id
  subnet_id       = aws_subnet.private[2].id
  security_groups = [aws_security_group.datalayer-sg.id]
}

# set second mount target for the EFS 
resource "aws_efs_mount_target" "subnet-2" {
  file_system_id  = aws_efs_file_system.ACS-efs.id
  subnet_id       = aws_subnet.private[3].id
  security_groups = [aws_security_group.datalayer-sg.id]
}

# create access point for wordpress
resource "aws_efs_access_point" "wordpress" {
  file_system_id = aws_efs_file_system.ACS-efs.id

  posix_user {
    gid = 0
    uid = 0
  }

  root_directory {
    path = "/wordpress"

    creation_info {
      owner_gid   = 0
      owner_uid   = 0
      permissions = 0755
    }

  }

}

# create access point for tooling
resource "aws_efs_access_point" "tooling" {
  file_system_id = aws_efs_file_system.ACS-efs.id
  posix_user {
    gid = 0
    uid = 0
  }

  root_directory {

    path = "/tooling"

    creation_info {
      owner_gid   = 0
      owner_uid   = 0
      permissions = 0755
    }

  }
}
```
### Creating an RDS instance

- Let's create an RDS instance. Add the following code to rds.tf file:

```
# This section will create the subnet group for the RDS  instance using the private subnet
resource "aws_db_subnet_group" "ACS-rds" {
  name       = "acs-rds"
  subnet_ids = [aws_subnet.private[2].id, aws_subnet.private[3].id]

 tags = merge(
    var.tags,
    {
      Name = format("%s-rds-%s", var.name, var.environment)
    },
  )
}

# create the RDS instance with the subnets group
resource "aws_db_instance" "ACS-rds" {
  allocated_storage      = 20
  storage_type           = "gp2"
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t2.micro"
  name                   = "mannydb"
  username               = var.master-username
  password               = var.master-password
  parameter_group_name   = "default.mysql5.7"
  db_subnet_group_name   = aws_db_subnet_group.ACS-rds.name
  skip_final_snapshot    = true
  vpc_security_group_ids = [aws_security_group.datalayer-sg.id]
  multi_az               = "true"
}
```
- Before Applying, if you take note, we gave reference to a lot of variables in our resources that has not been declared in the variables.tf file. Go through the entire code and spot these variables and declare them in the variables.tf file.

```

variable "region" {
  type = string
  description = "The region to deploy resources"
}

variable "vpc_cidr" {
  type = string
  description = "The VPC cidr"
}

variable "enable_dns_support" {
  type = bool
}

variable "enable_dns_hostnames" {
  dtype = bool
}

variable "enable_classiclink" {
  type = bool
}

variable "enable_classiclink_dns_support" {
  type = bool
}

variable "preferred_number_of_public_subnets" {
  type        = number
  description = "Number of public subnets"
}

variable "preferred_number_of_private_subnets" {
  type        = number
  description = "Number of private subnets"
}

variable "name" {
  type    = string
  default = "ACS"

}

variable "tags" {
  description = "A mapping of tags to assign to all resources."
  type        = map(string)
  default     = {}
}

variable "ami" {
  type        = string
  description = "AMI ID for the launch template"
}

variable "keypair" {
  type        = string
  description = "key pair for the instances"
}

variable "account_no" {
  type        = number
  description = "the account number"
}

variable "master-username" {
  type        = string
  description = "RDS admin username"
}

variable "master-password" {
  type        = string
  description = "RDS master password"
}
```
- Now, we are almost done but we need to update the last file which is terraform.tfvars file. In this file, we are going to declare the values for the variables in our variables.tf file.

```
region = "us-east-1"

vpc_cidr = "172.16.0.0/16"

enable_dns_support = "true"

enable_dns_hostnames = "true"

enable_classiclink = "false"

enable_classiclink_dns_support = "false"

preferred_number_of_public_subnets = "2"

preferred_number_of_private_subnets = "4"

environment = "production"

ami = "ami-0b0af3577fe5e3532"

keypair = "devops"

# Ensure to change this to your acccount number
account_no = "123456789"

db-username = "goddhi"

db-password = "goddhideops"
```
### Conclusion

We've been able to get all our infrastructure elements ready to be deployed automatically, but we still have a number of things that need to be resolved before deploying.

  - We need to divide the project into modules to ensure that it's easier to read and understand.

  - We need to fix the shell scripts that are needed for our RDS and EFS endpoints to be accessible from our EC2 instances.


We would do this in the next project.

### Additional Tasks

    1. Summarise your understanding on Networking concepts like IP Address, Subnets, CIDR Notation, IP Routing, Internet Gateways, NAT gateways.
    IP Address: An IP address is a unique identifier assigned to devices on a network that allows them to communicate with each other using the Internet Protocol. IP addresses are made up of four sets of numbers separated by periods, and they can be either IPv4 (32-bit) or IPv6 (128-bit).

    Subnets: A subnet is a smaller network within a larger network that allows devices to communicate with each other using a shared set of IP addresses. Subnets can be used to organize devices on a network and improve security by isolating different parts of the network.

    CIDR Notation: Classless Inter-Domain Routing (CIDR) notation is a way of representing IP addresses and subnets in a more concise format. CIDR notation combines the IP address with a number that indicates the number of bits in the subnet mask, which determines the range of IP addresses that are included in the subnet.

    IP Routing: IP routing is the process of forwarding packets of data between networks. Routing is performed by routers, which use a routing table to determine the best path for data to travel based on the destination IP address.

    Internet Gateways: An Internet gateway is a device that connects a local network to the Internet. Gateways typically perform network address translation (NAT) to allow devices on the local network to access the Internet using a shared public IP address.

    NAT: Network Address Translation (NAT) is a method of remapping one IP address space into another by modifying network address information in the IP header of packets while they are in transit across a traffic routing device. This allows multiple devices on a local network to share a single public IP address when communicating with the Internet.

  2.  Summarise your understanding of the OSI Model, TCP/IP suite and how they are connected – research beyond the provided articles, and watch different YouTube videos to fully understand the concept around OSI and how it is related to the Internet and end-to-end Web Solutions. You do not need to memorize the layers – just understand the idea around them.

The seven layers of the OSI Model are:

Physical Layer: This layer is responsible for the transmission and reception of raw bit streams over a physical medium.

Data Link Layer: This layer provides error-free transmission of data over a physical link by dividing data into frames and ensuring that they are transmitted without errors.

Network Layer: This layer is responsible for routing packets of data between different networks based on their IP addresses.

Transport Layer: This layer provides reliable transmission of data between applications by establishing a connection-oriented or connectionless communication channel.

Session Layer: This layer establishes, manages, and terminates sessions between applications running on different devices.

Presentation Layer: This layer is responsible for data translation, encryption, and compression to ensure that data can be understood by the receiving application.

Application Layer: This layer provides services to application programs and enables them to access network resources.

The TCP/IP suite (Transmission Control Protocol/Internet Protocol) is a set of protocols that enable communication between devices on the Internet. It is based on the OSI Model, but it combines some of the layers and simplifies others to create a more streamlined protocol stack.

The four layers of the TCP/IP suite are:

Link Layer: This layer is responsible for the physical transmission of data over a network.

Internet Layer: This layer provides routing of data packets over the Internet based on their IP addresses.

Transport Layer: This layer provides reliable communication between applications by establishing a connection-oriented or connectionless communication channel.

Application Layer: This layer provides services to application programs and enables them to access network resources.

The OSI Model and TCP/IP suite are connected in that they both provide a framework for understanding how different network protocols work together to facilitate communication between devices on a network. The TCP/IP suite is based on the OSI Model, but it simplifies and streamlines some of the layers to create a more efficient protocol stack. Together, they provide the foundation for end-to-end web solutions by enabling communication between devices on the Internet.

  3. Explain the difference between assume role policy and role policy

  The Assume Role Policy controls who can assume the role and under what conditions, while the Role Policy controls the permissions granted to the role and what actions can be performed by the entity assuming the role. Both policies are important for controlling access to AWS resources and ensuring the security of your AWS environment.

