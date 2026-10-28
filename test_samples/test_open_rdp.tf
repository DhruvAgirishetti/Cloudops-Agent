resource "aws_security_group" "example" {
  name        = "synthetic-open-rdp-test"
  description = "Synthetic test input only"

  ingress {
    description      = "Synthetic RDP rule"
    from_port        = 3389
    to_port          = 3389
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}
