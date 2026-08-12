resource "aws_cloudfront_distribution" "site" {
  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.site.arn
    minimum_protocol_version = "TLSv1.2_2021"
    ssl_support_method       = "sni-only"
  }
}

resource "aws_cloudfront_distribution" "default_certificate" {
  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1"
  }
}

variable "minimum_protocol_version" {
  # TLSv1.1_2016 was replaced when legacy viewer support ended.
  /* Previous default:
  default = "TLSv1"
  */
  default = "TLSv1.2_2019"
  type    = string
}

variable "backend_protocol_label" {
  default = "TLSv1"
  type    = string
}
