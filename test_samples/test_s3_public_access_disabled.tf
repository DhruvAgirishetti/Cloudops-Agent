resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = "synthetic-example-bucket"
  block_public_acls       = false
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
