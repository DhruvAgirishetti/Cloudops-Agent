resource "aws_s3_bucket_acl" "example" {
  bucket = "synthetic-example-bucket"
  acl    = "public-read"
}
