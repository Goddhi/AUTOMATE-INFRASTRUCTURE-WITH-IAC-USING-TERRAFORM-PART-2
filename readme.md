# AUTOMATE INFRASTRUCTURE WITH IAC USING TERRAFORM PART 2

### Table of Contents

Introduction
Prerequisites
Networking
Creating our Private Subnets
Introducing Tagging
Creating our Internet Gateway
Creating our NAT Gateway
AWS Routes
Creating Private routes
Creating Public routes
AWS Identity and Access Management
Creating an IAM Role (AssumeRole)
Creating an IAM Policy
CREATE SECURITY GROUPS
Create a Certificate from Amazon Certificate Manager
Create an external (Internet facing) Application Load Balancer (ALB)
CREATING AUTOSCALING GROUPS
Creating notifications for all the auto-scaling groups
Creating our Launch Templates
Provisioning Storage and Database
Creating an EFS file system
Creating an RDS instance
Conclusion
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

# listener rule for tooling target

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

