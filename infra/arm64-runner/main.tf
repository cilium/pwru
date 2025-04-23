# VPC setup
resource "aws_vpc" "vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.owner}/${var.gh_label}-runner"
  }
}

resource "aws_subnet" "subnet" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = var.zone
}

resource "aws_security_group" "security_group" {
  name = "allow-all"

  vpc_id = aws_vpc.vpc.id

  ingress {
    cidr_blocks = [
      "0.0.0.0/0"
    ]
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_internet_gateway" "gateway" {
  vpc_id = aws_vpc.vpc.id

  timeouts {
    delete = "60m"
  }
}

resource "aws_route_table" "route_table" {
  vpc_id = aws_vpc.vpc.id


  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gateway.id
  }
}

resource "aws_route_table_association" "route_table_association" {
  subnet_id      = aws_subnet.subnet.id
  route_table_id = aws_route_table.route_table.id
}

# SSH key
resource "aws_key_pair" "key_pair" {
  key_name   = var.ssh_key_pair
  public_key = var.ssh_public_key
}

# EC2 instance
resource "aws_instance" "runner" {
  instance_type               = var.ec2_type
  ami                         = var.ec2_ami
  key_name                    = var.ssh_key_pair
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.subnet.id
  vpc_security_group_ids      = ["${aws_security_group.security_group.id}"]

  root_block_device {
    volume_size = 256
    volume_type = "gp3"
  }

  user_data = replace(replace(replace(replace(replace(replace(replace(file("./setup.sh"),
    "{GITHUB_APP_ID}", var.gh_app_id),
    "{GITHUB_APP_INSTALL_ID}", var.gh_app_install_id),
    "{GITHUB_APP_PEM}", var.gh_app_pem),
    "{GITHUB_ORG}", var.gh_org),
    "{GITHUB_GROUP}", var.gh_group),
    "{GITHUB_LABELS}", var.gh_label),
  "{GITHUB_RUNNERS_COUNT}", var.gh_runners_count)

  lifecycle {
    ignore_changes = [user_data]
  }

  tags = {
    Name  = "${var.owner}/${var.gh_label}"
    Label = "${var.gh_label}"
  }

  timeouts {
    delete = "60m"
  }
}

