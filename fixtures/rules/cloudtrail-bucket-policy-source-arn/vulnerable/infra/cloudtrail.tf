data "aws_iam_policy_document" "cloudtrail" {
  statement {
    effect    = "Deny"
    actions   = ["s3:DeleteObject"]
    resources = ["${aws_s3_bucket.logs.arn}/*"]

    condition {
      test     = "ArnNotEquals"
      variable = "aws:SourceArn"
      values   = [aws_iam_role.retention.arn]
    }
  }

  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}
