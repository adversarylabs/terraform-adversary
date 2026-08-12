resource "aws_cloudfront_distribution" "site" {
  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.site.arn
    minimum_protocol_version = "TLSv1"
    ssl_support_method       = "sni-only"
  }
}

variable "minimum_protocol_version" {
  default     = "TLSv1.1_2016"
  description = "CloudFront viewer policy"
  type        = string
}
