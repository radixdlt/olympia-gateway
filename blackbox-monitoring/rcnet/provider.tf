provider "aws" {
  region = var.aws_region
}

data "aws_secretsmanager_secret" "grafana-cloud-api-key" {
  name = "testnets/grafana-cloud-api-key"
}

data "aws_secretsmanager_secret" "grafana-sm-token" {
  name = "development/sm-access-token"
}

data "aws_secretsmanager_secret" "grafana-cloud-url" {
  name = "development/grafana-cloud-url"
}

data "aws_secretsmanager_secret_version" "grafana-cloud-api-key" {
  secret_id = data.aws_secretsmanager_secret.grafana-cloud-api-key.id
}

data "aws_secretsmanager_secret_version" "grafana-sm-token" {
  secret_id = data.aws_secretsmanager_secret.grafana-sm-token.id
}

data "aws_secretsmanager_secret_version" "grafana-cloud-url" {
  secret_id = data.aws_secretsmanager_secret.grafana-cloud-url.id
}

provider "grafana" {
  url = jsondecode(data.aws_secretsmanager_secret_version.grafana-cloud-url.secret_string)["GRAFANA_CLOUD_URL"]
  auth            = jsondecode(data.aws_secretsmanager_secret_version.grafana-cloud-api-key.secret_string)["GRAFANA_CLOUD_API_KEY"]
  sm_access_token = jsondecode(data.aws_secretsmanager_secret_version.grafana-sm-token.secret_string)["GRAFANA_SM_ACCESS_TOKEN"]
}

terraform {
  required_providers {
    grafana = {
      source  = "grafana/grafana"
      version = ">=1.13.4"
    }
  }

  backend "s3" {
    bucket = "radixdlt-blackbox-grafana-monitoring-state"
    key    = "blackbox-monitoring/network-gateway/rcnet/terraform.tfstate"
    region = "eu-west-1"
    dynamodb_table = "blackbox-grafana-monitoring-up-and-running-locks"
    encrypt        = true
  }
}
