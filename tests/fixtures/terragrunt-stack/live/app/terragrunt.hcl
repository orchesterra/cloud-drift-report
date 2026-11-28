include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "../../modules/file"
}

dependency "vpc" {
  config_path = "../vpc"
}

inputs = {
  filename = "${get_terragrunt_dir()}/out.txt"
  content  = dependency.vpc.outputs.id
}
