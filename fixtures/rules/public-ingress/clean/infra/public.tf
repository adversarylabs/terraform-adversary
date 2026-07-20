resource "aws_security_group_rule" "private" { cidr_blocks = ["10.0.0.0/8"] from_port = 443 to_port = 443 }
