terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
  backend "s3" {
    bucket  = "tf-states-backup-nameistaken"
    region  = "eu-central-1"
    key     = "latency/terraform.tfstate"
    profile = "personal"
  }
}

provider "aws" {
  region                   = "us-east-1"
  shared_credentials_files = ["~/.aws/credentials"]
  profile                  = "personal"
}

provider "aws" {
  alias  = "us-west-1"
  region = "us-west-1"

  shared_credentials_files = ["~/.aws/credentials"]
  profile                  = "personal"
}

provider "aws" {
  alias  = "sa-east-1"
  region = "sa-east-1"

  shared_credentials_files = ["~/.aws/credentials"]
  profile                  = "personal"
}

provider "aws" {
  alias  = "eu-west-1"
  region = "eu-west-1"

  shared_credentials_files = ["~/.aws/credentials"]
  profile                  = "personal"
}

provider "aws" {
  alias  = "eu-north-1"
  region = "eu-north-1"

  shared_credentials_files = ["~/.aws/credentials"]
  profile                  = "personal"
}

provider "aws" {
  alias  = "eu-central-1"
  region = "eu-central-1"

  shared_credentials_files = ["~/.aws/credentials"]
  profile                  = "personal"
}

provider "aws" {
  alias  = "af-south-1"
  region = "af-south-1"

  shared_credentials_files = ["~/.aws/credentials"]
  profile                  = "personal"
}

provider "aws" {
  alias  = "ap-south-1"
  region = "ap-south-1"

  shared_credentials_files = ["~/.aws/credentials"]
  profile                  = "personal"
}

provider "aws" {
  alias  = "ap-southeast-1"
  region = "ap-southeast-1"

  shared_credentials_files = ["~/.aws/credentials"]
  profile                  = "personal"
}

provider "aws" {
  alias  = "ap-southeast-2"
  region = "ap-southeast-2"

  shared_credentials_files = ["~/.aws/credentials"]
  profile                  = "personal"
}

provider "aws" {
  alias  = "ap-northeast-1"
  region = "ap-northeast-1"

  shared_credentials_files = ["~/.aws/credentials"]
  profile                  = "personal"
}

data "aws_iam_policy_document" "assume_lambda_policy" {
  version = "2012-10-17"
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_iam_role" {
  assume_role_policy = data.aws_iam_policy_document.assume_lambda_policy.json
  name               = "latency-lambda-role"
}

resource "aws_iam_role_policy_attachment" "lambda_policy" {
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}


module "us-east-1" {
  source            = "./modules/region"
  region            = "us-east-1"
  iam_role_arn      = aws_iam_role.lambda_iam_role.arn
  cloudfront_secret = random_password.cloudfront_to_lambda_secret.result

  providers = {
    aws = aws
  }
}

module "us-west-1" {
  source            = "./modules/region"
  region            = "us-west-1"
  iam_role_arn      = aws_iam_role.lambda_iam_role.arn
  cloudfront_secret = random_password.cloudfront_to_lambda_secret.result

  providers = {
    aws = aws.us-west-1
  }
}

module "sa-east-1" {
  source            = "./modules/region"
  region            = "sa-east-1"
  iam_role_arn      = aws_iam_role.lambda_iam_role.arn
  cloudfront_secret = random_password.cloudfront_to_lambda_secret.result

  providers = {
    aws = aws.sa-east-1
  }
}

module "eu-west-1" {
  source            = "./modules/region"
  region            = "eu-west-1"
  iam_role_arn      = aws_iam_role.lambda_iam_role.arn
  cloudfront_secret = random_password.cloudfront_to_lambda_secret.result

  providers = {
    aws = aws.eu-west-1
  }
}

module "eu-north-1" {
  source            = "./modules/region"
  region            = "eu-north-1"
  iam_role_arn      = aws_iam_role.lambda_iam_role.arn
  cloudfront_secret = random_password.cloudfront_to_lambda_secret.result

  providers = {
    aws = aws.eu-north-1
  }
}

module "eu-central-1" {
  source            = "./modules/region"
  region            = "eu-central-1"
  iam_role_arn      = aws_iam_role.lambda_iam_role.arn
  cloudfront_secret = random_password.cloudfront_to_lambda_secret.result

  providers = {
    aws = aws.eu-central-1
  }
}

module "af-south-1" {
  source            = "./modules/region"
  region            = "af-south-1"
  iam_role_arn      = aws_iam_role.lambda_iam_role.arn
  cloudfront_secret = random_password.cloudfront_to_lambda_secret.result

  providers = {
    aws = aws.af-south-1
  }
}

module "ap-south-1" {
  source            = "./modules/region"
  region            = "ap-south-1"
  iam_role_arn      = aws_iam_role.lambda_iam_role.arn
  cloudfront_secret = random_password.cloudfront_to_lambda_secret.result

  providers = {
    aws = aws.ap-south-1
  }
}

module "ap-southeast-1" {
  source            = "./modules/region"
  region            = "ap-southeast-1"
  iam_role_arn      = aws_iam_role.lambda_iam_role.arn
  cloudfront_secret = random_password.cloudfront_to_lambda_secret.result

  providers = {
    aws = aws.ap-southeast-1
  }
}

module "ap-southeast-2" {
  source            = "./modules/region"
  region            = "ap-southeast-2"
  iam_role_arn      = aws_iam_role.lambda_iam_role.arn
  cloudfront_secret = random_password.cloudfront_to_lambda_secret.result

  providers = {
    aws = aws.ap-southeast-2
  }
}

module "ap-northeast-1" {
  source            = "./modules/region"
  region            = "ap-northeast-1"
  iam_role_arn      = aws_iam_role.lambda_iam_role.arn
  cloudfront_secret = random_password.cloudfront_to_lambda_secret.result

  providers = {
    aws = aws.ap-northeast-1
  }
}

resource "aws_s3_bucket" "bucket" {
  bucket        = "latency-website"
  force_destroy = true
}

resource "aws_s3_bucket_object" "index_page" {
  bucket       = aws_s3_bucket.bucket.bucket
  key          = "index.html"
  source       = "${abspath("../website")}/index.html"
  etag         = filemd5("${abspath("../website")}/index.html")
  content_type = "text/html"
}

resource "aws_cloudfront_origin_access_control" "oac" {
  name                              = "latency-cloudfront-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

data "aws_iam_policy_document" "allow_access_from_cloudfront" {
  statement {
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    actions = [
      "s3:GetObject",
    ]

    resources = [
      "${aws_s3_bucket.bucket.arn}/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.distribution.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "allow_access_from_cloudfront" {
  bucket = aws_s3_bucket.bucket.id
  policy = data.aws_iam_policy_document.allow_access_from_cloudfront.json
}

resource "aws_cloudfront_cache_policy" "policy" {
  name = "latency-cloudfront-cache-policy"

  default_ttl = 0
  max_ttl     = 0
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

resource "aws_cloudfront_origin_request_policy" "policy" {
  name = "latency-cloudfront-api-request-policy"
  cookies_config {
    cookie_behavior = "none"
  }
  headers_config {
    header_behavior = "none"
  }
  query_strings_config {
    query_string_behavior = "whitelist"
    query_strings {
      items = ["url"]
    }
  }
}

resource "random_password" "cloudfront_to_lambda_secret" {
  length  = 16
  special = true
}

resource "aws_cloudfront_distribution" "distribution" {
  enabled             = true
  price_class         = "PriceClass_All"
  default_root_object = "index.html"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  origin {
    domain_name              = aws_s3_bucket.bucket.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
    origin_id                = "website-bucket"
  }

  origin {
    origin_id   = "lambda-us-east-1"
    domain_name = replace(module.us-east-1.function_url, "/^https?://([^/]*).*/", "$1")

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "x-latency-secret"
      value = random_password.cloudfront_to_lambda_secret.result
    }
  }

  origin {
    origin_id   = "lambda-us-west-1"
    domain_name = replace(module.us-west-1.function_url, "/^https?://([^/]*).*/", "$1")

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "x-latency-secret"
      value = random_password.cloudfront_to_lambda_secret.result
    }
  }

  origin {
    origin_id   = "lambda-sa-east-1"
    domain_name = replace(module.sa-east-1.function_url, "/^https?://([^/]*).*/", "$1")

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "x-latency-secret"
      value = random_password.cloudfront_to_lambda_secret.result
    }
  }

  origin {
    origin_id   = "lambda-eu-west-1"
    domain_name = replace(module.eu-west-1.function_url, "/^https?://([^/]*).*/", "$1")

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "x-latency-secret"
      value = random_password.cloudfront_to_lambda_secret.result
    }
  }

  origin {
    origin_id   = "lambda-eu-north-1"
    domain_name = replace(module.eu-north-1.function_url, "/^https?://([^/]*).*/", "$1")

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "x-latency-secret"
      value = random_password.cloudfront_to_lambda_secret.result
    }
  }

  origin {
    origin_id   = "lambda-eu-central-1"
    domain_name = replace(module.eu-central-1.function_url, "/^https?://([^/]*).*/", "$1")

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "x-latency-secret"
      value = random_password.cloudfront_to_lambda_secret.result
    }
  }

  origin {
    origin_id   = "lambda-af-south-1"
    domain_name = replace(module.af-south-1.function_url, "/^https?://([^/]*).*/", "$1")

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "x-latency-secret"
      value = random_password.cloudfront_to_lambda_secret.result
    }
  }

  origin {
    origin_id   = "lambda-ap-south-1"
    domain_name = replace(module.ap-south-1.function_url, "/^https?://([^/]*).*/", "$1")

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "x-latency-secret"
      value = random_password.cloudfront_to_lambda_secret.result
    }
  }

  origin {
    origin_id   = "lambda-ap-southeast-1"
    domain_name = replace(module.ap-southeast-1.function_url, "/^https?://([^/]*).*/", "$1")

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "x-latency-secret"
      value = random_password.cloudfront_to_lambda_secret.result
    }
  }

  origin {
    origin_id   = "lambda-ap-southeast-2"
    domain_name = replace(module.ap-southeast-2.function_url, "/^https?://([^/]*).*/", "$1")

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "x-latency-secret"
      value = random_password.cloudfront_to_lambda_secret.result
    }
  }

  origin {
    origin_id   = "lambda-ap-northeast-1"
    domain_name = replace(module.ap-northeast-1.function_url, "/^https?://([^/]*).*/", "$1")

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "x-latency-secret"
      value = random_password.cloudfront_to_lambda_secret.result
    }
  }

  default_cache_behavior {
    allowed_methods  = ["HEAD", "GET"]
    cached_methods   = ["HEAD", "GET"]
    target_origin_id = "website-bucket"

    cache_policy_id = aws_cloudfront_cache_policy.policy.id

    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  ordered_cache_behavior {
    path_pattern     = "/api/v1/us-east-1"
    allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods   = ["HEAD", "GET"]
    target_origin_id = "lambda-us-east-1"

    cache_policy_id          = aws_cloudfront_cache_policy.policy.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.policy.id


    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  ordered_cache_behavior {
    path_pattern     = "/api/v1/us-west-1"
    allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods   = ["HEAD", "GET"]
    target_origin_id = "lambda-us-west-1"

    cache_policy_id          = aws_cloudfront_cache_policy.policy.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.policy.id


    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  ordered_cache_behavior {
    path_pattern     = "/api/v1/sa-east-1"
    allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods   = ["HEAD", "GET"]
    target_origin_id = "lambda-sa-east-1"

    cache_policy_id          = aws_cloudfront_cache_policy.policy.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.policy.id


    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  ordered_cache_behavior {
    path_pattern     = "/api/v1/eu-west-1"
    allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods   = ["HEAD", "GET"]
    target_origin_id = "lambda-eu-west-1"

    cache_policy_id          = aws_cloudfront_cache_policy.policy.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.policy.id


    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  ordered_cache_behavior {
    path_pattern     = "/api/v1/eu-north-1"
    allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods   = ["HEAD", "GET"]
    target_origin_id = "lambda-eu-north-1"

    cache_policy_id          = aws_cloudfront_cache_policy.policy.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.policy.id


    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  ordered_cache_behavior {
    path_pattern     = "/api/v1/eu-central-1"
    allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods   = ["HEAD", "GET"]
    target_origin_id = "lambda-eu-central-1"

    cache_policy_id          = aws_cloudfront_cache_policy.policy.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.policy.id


    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  ordered_cache_behavior {
    path_pattern     = "/api/v1/af-south-1"
    allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods   = ["HEAD", "GET"]
    target_origin_id = "lambda-af-south-1"

    cache_policy_id          = aws_cloudfront_cache_policy.policy.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.policy.id


    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  ordered_cache_behavior {
    path_pattern     = "/api/v1/ap-south-1"
    allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods   = ["HEAD", "GET"]
    target_origin_id = "lambda-ap-south-1"

    cache_policy_id          = aws_cloudfront_cache_policy.policy.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.policy.id


    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  ordered_cache_behavior {
    path_pattern     = "/api/v1/ap-southeast-1"
    allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods   = ["HEAD", "GET"]
    target_origin_id = "lambda-ap-southeast-1"

    cache_policy_id          = aws_cloudfront_cache_policy.policy.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.policy.id


    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  ordered_cache_behavior {
    path_pattern     = "/api/v1/ap-southeast-2"
    allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods   = ["HEAD", "GET"]
    target_origin_id = "lambda-ap-southeast-1"

    cache_policy_id          = aws_cloudfront_cache_policy.policy.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.policy.id


    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  ordered_cache_behavior {
    path_pattern     = "/api/v1/ap-northeast-1"
    allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods   = ["HEAD", "GET"]
    target_origin_id = "lambda-ap-northeast-1"

    cache_policy_id          = aws_cloudfront_cache_policy.policy.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.policy.id


    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }
}

output "cf_distribution_url" {
  value = aws_cloudfront_distribution.distribution.domain_name
}
