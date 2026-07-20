resource azurerm_kubernetes_cluster "k8s_cluster" {
  dns_prefix          = "terragoat-${var.environment}"
  location            = var.location
  name                = "terragoat-aks-${var.environment}"
  resource_group_name = azurerm_resource_group.example.name
  kubernetes_version  = "1.28.9"
  private_cluster_enabled = true
  api_server_authorized_ip_ranges = ["10.0.0.0/16"]
  local_account_disabled = true
  disk_encryption_set_id = azurerm_disk_encryption_set.example.id
  identity {
    type = "SystemAssigned"
  }
  default_node_pool {
    name       = "default"
    vm_size    = "Standard_D2_v2"
    node_count = 2
    vnet_subnet_id = azurerm_subnet.example.id
    enable_auto_scaling = true
    min_count = 1
    max_count = 3
  }
  network_profile {
    network_policy = "azure"
  }
  addon_profile {
    oms_agent {
      enabled = true
    }
    kube_dashboard {
      enabled = false
    }
    azure_policy {
      enabled = true
    }
  }
  role_based_access_control {
    enabled = true
  }
  tags = {
    git_commit           = "898d5beaec7ffdef6df0d7abecff407362e2a74e"
    git_file             = "terraform/azure/aks.tf"
    git_last_modified_at = "2020-06-17 12:59:55"
    git_last_modified_by = "nimrodkor@gmail.com"
    git_modifiers        = "nimrodkor"
    git_org              = "bridgecrewio"
    git_repo             = "terragoat"
    yor_trace            = "6103d111-864e-42e5-899c-1864de281fd1"
  }
}