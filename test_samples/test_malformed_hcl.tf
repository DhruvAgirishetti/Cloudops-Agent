resource "aws_security_group" "broken" {
  name = "synthetic-malformed-test"

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"
  }
}
