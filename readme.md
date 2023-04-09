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


