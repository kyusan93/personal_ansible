variable "vms" {
  type = map
  default = {
    JG_MC1 = {
      name = "JG_MC1_2.160"
    },
    JG_MC2 = {
      name = "JG_MC2_2.161"
    },
    JG_SH11 = {
      name = "JG_SH11_2.162"
    },
    JG_SH12 = {
      name = "JG_SH12_2.163"
    },
    JG_SH13 = {
      name = "JG_SH13_2.164"
    },
    JG_IDX11 = {
      name = "JG_IDX11_2.165"
    },
    JG_IDX12 = {
      name = "JG_IDX12_2.166"
    },
    JG_IDX13 = {
      name = "JG_IDX13_2.167"
    },
    JG_IDX14 = {
      name = "JG_IDX14_2.168"
    },
    JG_HF11 = {
      name = "JG_HF11_2.169"
    },
  }
}

locals {
  vsphere_user = "administrator@vsphere.local"
  vsphere_password = "P@ssw0rd"
  vsphere_server = "192.168.1.5"
  datacenter_name = "InternalLab"
  datastore_name = "data(2)"
  resource_pool = "pool"
}

provider "vsphere" {
  user = local.vsphere_user
  password = local.vsphere_password
  vsphere_server = local.vsphere_server
  allow_unverified_ssl = true
}

output "local" {
  value = "${local.vsphere_server}"
}

