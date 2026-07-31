data "aws_iam_policy_document" "read" {
  statement {
    actions = ["s3:GetObject"]
    resources = ["arn:aws:s3:::bucket/*"]
  }
}
