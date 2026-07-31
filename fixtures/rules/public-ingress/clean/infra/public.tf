resource "aws_security_group_rule" "https" {
  type              = "ingress"
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
}

resource "aws_security_group_rule" "private_ssh" {
  type              = "ingress"
  cidr_blocks       = ["10.0.0.0/8"]
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
}
