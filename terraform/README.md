# Terraform (AWS skeleton)

A deliberately small starting point: **ECR** (immutable tags, scan-on-push) and an
**ECS Fargate** service with least-privilege IAM, read-only root filesystem,
non-root user, CloudWatch logs and a deployment circuit breaker.

It has **not been applied** - it was written without AWS credentials or a
Terraform binary available, so treat it as reviewed-but-untested IaC.

Assumed to exist already (pass in as variables): VPC + private subnets, an ALB
and its security group, and Secrets Manager entries for `VG_DATABASE_URL` /
`VG_REDIS_URL`.

Not yet covered: RDS Postgres, ElastiCache Redis, ALB target group wiring, WAF,
mounting JWT / master-key files into Fargate (EFS or an init container), and a
KMS-backed `KeyProvider` (the task role is where its `kms:Decrypt` permission goes).

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # edit
terraform init && terraform plan
```
