variable "region" {}
variable "iam_role_arn" {}
variable "cloudfront_secret" {}

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

data "archive_file" "lambda" {
  type        = "zip"
  source_file = "../build/lambda"
  output_path = "../build/lambda.zip"
}

resource "aws_lambda_function" "function" {
  filename         = data.archive_file.lambda.output_path
  source_code_hash = filebase64sha256(data.archive_file.lambda.output_path)
  function_name    = "latency-lambda"
  role             = var.iam_role_arn
  handler          = "lambda"
  runtime          = "go1.x"
  memory_size      = 128
  timeout          = 15

  environment {
    variables = {
      LATENCY_AWS_REGION        = var.region
      LATENCY_CLOUDFRONT_SECRET = var.cloudfront_secret
    }
  }
}

resource "aws_lambda_function_url" "function" {
  function_name      = aws_lambda_function.function.function_name
  authorization_type = "NONE"
}

output "function_url" {
  value = aws_lambda_function_url.function.function_url
}
