output "db_password" { value = aws_db_instance.db.password sensitive = true }
output "endpoint" { value = aws_db_instance.db.address }
