data "vsphere_datacenter" "dc" {
  name = local.datacenter_name
}

data "vsphere_resource_pool" "pool" {
  name = var.resource_pool
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_datastore" "datastore" {
  name = local.datastore_name
  datacenter_id = data.vsphere_datacenter.dc.id
}

resource "vsphere_virtual_machine" "vm" {
  for_each = var.vms
  name = each.value.name
  resource_pool_id = data.vsphere_resource_pool.pool.id
  datastore_id = data.vsphere_datastore.datastore.id
}

#output "vm_uuid" {
#  value = vsphere_virtual_machine.vm.uuid
#}

output "vm_uuid" {
  value = [
    for vm in vsphere_virtual_machine.vm : vm.uuid
  ]
}

