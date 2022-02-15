
data "grafana_synthetic_monitoring_probes" "public-probes" {}

module "synthentic-monitoring" {
  source = "git@github.com:radixdlt/radixdlt-iac.git//terraform/modules/common/blackbox-monitoring?ref=master"
  grafana_api_key_path = "testnets/grafana-cloud-api-key"
  sm_access_token_path = "development/sm-access-token"
  grafana_cloud_url_path = "development/grafana-cloud-url"
  aws_region = var.aws_region
  probes_list = [
    data.grafana_synthetic_monitoring_probes.public-probes.probes.London
  ]
  check_enabled = true
  target_address = "https://rcnet-gateway.radixdlt.com"
  target_domain_name = "rcnet-gateway.radixdlt.com"
  project_name = "network-gateway"
  environment_name = "rcnet"
}
