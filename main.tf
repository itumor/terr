locals {
  instance_count = var.instance_enabled ? 1 : 0
    # create an instance profile if the instance is enabled and we aren't given
    # one to use
  instance_profile_count = var.instance_enabled ? 0 : length(var.instance_profile) > 0 ? 0 : 1
  instance_profile = local.instance_profile_count == 0 ? var.instance_profile : join("", aws_iam_instance_profile.default.*.name)
  security_group_count = var.create_default_security_group ? 1 : 0
  region = var.region != "" ? var.region : data.aws_region.default.name
  root_iops = var.root_volume_type == "io1" ? var.root_iops : "0"
  ebs_iops = var.ebs_volume_type == "io1" ? var.ebs_iops : "0"
  availability_zone = var.availability_zone != "" ? var.availability_zone : data.aws_subnet.default.availability_zone
  ami = var.ami != "" ? var.ami : join("", data.aws_ami.default.*.image_id)
  ami_owner = var.ami != "" ? var.ami_owner : join("", data.aws_ami.default.*.owner_id)
  root_volume_type = var.root_volume_type != "" ? var.root_volume_type : data.aws_ami.info.root_device_type
  public_dns = var.associate_public_ip_address && var.assign_eip_address && var.instance_enabled ? data.null_data_source.eip.outputs["public_dns"] : join("", aws_instance.default.*.public_dns)
}

data "aws_caller_identity" "default" {}

data "aws_region" "default" {}

data "aws_partition" "default" {}

data "aws_subnet" "default" {
  id = var.subnet
}

data "aws_iam_policy_document" "default" {
  statement {
    sid = ""
    actions = [
      "sts:AssumeRole",
    ]
    principals {
      type = "Service"
      identifiers = [
        "ec2.amazonaws.com",
      ]
    }
    effect = "Allow"
  }
}

data "aws_ami" "default" {
  count = var.ami == "" ? 1 : 0
  most_recent = "true"
  filter {
    name = "name"
    values = [
      "ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*",
    ]
  }
  filter {
    name = "virtualization-type"
    values = [
      "hvm",
    ]
  }
  owners = [
    "099720109477",
  ]
}

data "aws_ami" "info" {
  filter {
    name = "image-id"
    values = [
      local.ami,
    ]
  }
  owners = [
    local.ami_owner,
  ]
}

data "aws_iam_instance_profile" "given" {
  count = var.instance_enabled && length(var.instance_profile) > 0 ? 1 : 0
  name = var.instance_profile
}

module "label" {
  source = "git::https://github.com/cloudposse/terraform-null-label.git?ref=tags/0.16.0"
  namespace = var.namespace
  stage = var.stage
  environment = var.environment
  name = var.name
  attributes = var.attributes
  delimiter = var.delimiter
  enabled = var.instance_enabled
  tags = var.tags
}

resource "aws_iam_instance_profile" "default" {
  count = local.instance_profile_count
  name = module.label.id
  role = join("", aws_iam_role.default.*.name)
}

resource "aws_iam_role" "default" {
  count = local.instance_profile_count
  name = module.label.id
  path = "/"
  assume_role_policy = data.aws_iam_policy_document.default.json
  permissions_boundary = var.permissions_boundary_arn
}

resource "aws_instance" "default" {
  count = local.instance_count
  ami = local.ami
  availability_zone = local.availability_zone
  instance_type = var.instance_type
  ebs_optimized = var.ebs_optimized
  disable_api_termination = var.disable_api_termination
  user_data = var.user_data
  iam_instance_profile = local.instance_profile
  associate_public_ip_address = var.associate_public_ip_address
  key_name = var.ssh_key_pair
  subnet_id = var.subnet
  monitoring = var.monitoring
  private_ip = var.private_ip
  source_dest_check = var.source_dest_check
  ipv6_address_count = var.ipv6_address_count < 0 ? null : var.ipv6_address_count
  ipv6_addresses = length(var.ipv6_addresses) == 0 ? null : var.ipv6_addresses
  vpc_security_group_ids = compact(
concat(
[
var.create_default_security_group ? join("", aws_security_group.default.*.id) : "", 
], 
var.security_groups
)
)
  root_block_device {
    volume_type = local.root_volume_type
    volume_size = var.root_volume_size
    iops = local.root_iops
    delete_on_termination = var.delete_on_termination
  }
  tags = module.label.tags
}

resource "aws_eip" "default" {
  count = var.associate_public_ip_address && var.assign_eip_address && var.instance_enabled ? 1 : 0
  network_interface = join("", aws_instance.default.*.primary_network_interface_id)
  vpc = true
  tags = module.label.tags
}

data "null_data_source" "eip" {
  inputs = {
    public_dns = "ec2-${replace(join("",aws_eip.default.*.public_ip),".","-")}.${local.region=="us-east-1"?"compute-1":"${local.region}.compute"}.amazonaws.com"
  }
}

resource "aws_ebs_volume" "default" {
  count = var.ebs_volume_count
  availability_zone = local.availability_zone
  size = var.ebs_volume_size
  iops = local.ebs_iops
  type = var.ebs_volume_type
  tags = module.label.tags
}

resource "aws_volume_attachment" "default" {
  count = var.ebs_volume_count
  device_name = var.ebs_device_name[count.index]
  volume_id = aws_ebs_volume.default.*.id[count.index]
  instance_id = join("", aws_instance.default.*.id)
}

module "lb-http" {
  source = "GoogleCloudPlatform/lb-http/google"
  version = "4.1.0"
    # IP version for the Global address (IPv4 or v6) - Empty defaults to IPV4
  ip_version = ""
    # IP address self link
  address = ""
    # Selfink to SSL Policy
  ssl_policy = ""
    # The url_map resource to use. Default is to send all traffic to first backend.
  url_map = ""
    # Name for the forwarding rule and prefix for supporting resources
  name = ""
    # Content of the SSL certificate. Required if `ssl` is `true` and `ssl_certificates` is empty.
  certificate = ""
    # Content of the private SSL key. Required if `ssl` is `true` and `ssl_certificates` is empty.
  private_key = ""
    # Map backend indices to list of backend maps.
  backends = {  }
    # The project to deploy to, if not set the default provider project is used.
  project = ""
    # The resource URL for the security policy to associate with the backend service
  security_policy = ""
}

provider "aws" {}

module "nat-gateway" {
  source = "GoogleCloudPlatform/nat-gateway/google"
  version = "1.2.3"
    # The region to create the nat gateway instance in.
  region = ""
}

module "lb-internal" {
  source = "GoogleCloudPlatform/lb-internal/google"
  version = "2.2.0"
    # Name for the forwarding rule and prefix for supporting resources.
  name = ""
    # Service label is used to create internal DNS name
  service_label = ""
    # IP address of the internal load balancer, if empty one will be assigned. Default is empty.
  ip_address = ""
    # List of target tags for traffic between the internal load balancer.
  target_tags = [  ]
    # List of source tags for traffic between the internal load balancer.
  source_tags = [  ]
    # List of source ip ranges for traffic between the internal load balancer.
  source_ip_ranges = [  ]
    # Health check to determine whether instances are responsive and able to do work
  health_check = {  }
    # List of source service accounts for traffic between the internal load balancer.
  source_service_accounts = [  ]
    # Boolean for all_ports setting on forwarding rule.
  all_ports = false
    # List of ports range to forward to backend services. Max is 5.
  ports = [  ]
    # List of target service accounts for traffic between the internal load balancer.
  target_service_accounts = [  ]
    # List of backends, should be a map of key-value pairs for each backend, must have the 'group' key.
  backends = [  ]
}

module "network" {
  source = "Azure/network/azurerm"
  version = "3.1.1"
    # The name of an existing resource group to be imported.
  resource_group_name = ""
}

resource "aws_acmpca_certificate_authority" "" {
  certificate_authority_configuration {
    subject {    }
    key_algorithm = 
    signing_algorithm = 
  }
}

resource "aws_acm_certificate_validation" "" {
  certificate_arn = 
}

resource "aws_acm_certificate" "" {}

resource "aws_accessanalyzer_analyzer" "" {
  analyzer_name = 
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "2.44.0"
    # Assign IPv6 address on public subnet, must be disabled to change IPv6 CIDRs. This is the IPv6 equivalent of map_public_ip_on_launch
  public_subnet_assign_ipv6_address_on_creation = false
    # The fields to include in the flow log record, in the order in which they should appear.
  flow_log_log_format = ""
    # List of maps of ingress rules to set on the default security group
  default_security_group_ingress = [  ]
    # Assign IPv6 address on private subnet, must be disabled to change IPv6 CIDRs. This is the IPv6 equivalent of map_public_ip_on_launch
  private_subnet_assign_ipv6_address_on_creation = false
    # Assign IPv6 address on redshift subnet, must be disabled to change IPv6 CIDRs. This is the IPv6 equivalent of map_public_ip_on_launch
  redshift_subnet_assign_ipv6_address_on_creation = false
    # The Availability Zone for the VPN Gateway
  vpn_gateway_az = ""
    # List of maps of egress rules to set on the default security group
  default_security_group_egress = [  ]
    # The ARN of the KMS Key to use when encrypting log data for VPC flow logs.
  flow_log_cloudwatch_log_group_kms_key_id = ""
    # Should be true to enable ClassicLink for the VPC. Only valid in regions and accounts that support EC2 Classic.
  enable_classiclink = false
    # Specifies the number of days you want to retain log events in the specified log group for VPC flow logs.
  flow_log_cloudwatch_log_group_retention_in_days = 1
    # Should be true to enable ClassicLink DNS Support for the VPC. Only valid in regions and accounts that support EC2 Classic.
  enable_classiclink_dns_support = false
    # Assign IPv6 address on database subnet, must be disabled to change IPv6 CIDRs. This is the IPv6 equivalent of map_public_ip_on_launch
  database_subnet_assign_ipv6_address_on_creation = false
    # Assign IPv6 address on intra subnet, must be disabled to change IPv6 CIDRs. This is the IPv6 equivalent of map_public_ip_on_launch
  intra_subnet_assign_ipv6_address_on_creation = false
    # Assign IPv6 address on elasticache subnet, must be disabled to change IPv6 CIDRs. This is the IPv6 equivalent of map_public_ip_on_launch
  elasticache_subnet_assign_ipv6_address_on_creation = false
}

data "aws_arn" "" {
  arn = 
}

data "aws_autoscaling_group" "" {
  name = 
}
