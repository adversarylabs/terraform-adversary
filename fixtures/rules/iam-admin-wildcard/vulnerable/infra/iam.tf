data "aws_iam_policy_document" "admin" {
  statement {
    actions = ["*"]
    resources = ["*"]
  }
}
