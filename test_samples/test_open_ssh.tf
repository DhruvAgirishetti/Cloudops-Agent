resource "aws_security_group" "example" {
  name        = "synthetic-open-ssh-test"
  description = "Synthetic test input only"

  ingress {
    description = "Synthetic SSH rule"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
