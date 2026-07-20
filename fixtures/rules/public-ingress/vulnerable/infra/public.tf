resource "aws_security_group_rule" "public" { cidr_blocks = ["0.0.0.0/0"] from_port = 22 to_port = 22 }
