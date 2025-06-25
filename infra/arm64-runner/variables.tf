# SSH
variable "ssh_key_pair" {
  description = "SSH key pair name"
  type        = string
}

variable "ssh_public_key" {
  description = "SSH public key"
  type        = string
  sensitive   = true
}

# instance tags
variable "owner" {
  description = "Team responsible for the instance."
  type        = string
}

variable "region" {
  description = "The region in which to create the instance."
  type        = string
}

variable "zone" {
  description = "The availability zone in which to create the instance."
  type        = string
}

# multi-runners setup
variable "gh_app_id" {
  description = "GitHub App ID for runners management."
  type        = number
  sensitive   = true
}

variable "gh_app_install_id" {
  description = "GitHub App installation ID for runners management."
  type        = number
  sensitive   = true
}

variable "gh_app_pem" {
  description = "GitHub App private key for runners management."
  type        = string
  sensitive   = true
}

variable "gh_org" {
  description = "GitHub organization to register the runner against."
  type        = string
}

variable "gh_group" {
  description = "GitHub runners group to register the runner against."
  type        = string
}

variable "gh_label" {
  description = "GitHub runners label to register with."
  type        = string
}

variable "ec2_type" {
  description = "EC2 instance type."
  type        = string
}

variable "ec2_ami" {
  description = "EC2 instance AMI."
  type        = string
}

variable "gh_runners_count" {
  description = "GitHub runners count."
  type        = string
}

