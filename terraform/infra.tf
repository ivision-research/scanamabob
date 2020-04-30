provider "aws" {
  profile    = "default"
  region     = "us-east-1"
}

resource "aws_s3_bucket" "b" {
  bucket = "carve-scanamabob-test-bucket"
  acl    = "public-read-write"

  tags = {
    Name        = "Scanamabob Bucket"
    Environment = "Dev"
  }
}
