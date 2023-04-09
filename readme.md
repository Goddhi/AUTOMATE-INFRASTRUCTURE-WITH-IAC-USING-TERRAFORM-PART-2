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








