terraform {
  required_version = ">= 1.9, < 2.0"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 7.4" }
  }
}
provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}
variable "project_id" { type = string }
variable "name" {
  type    = string
  default = "toolbox"
}
variable "region" {
  type    = string
  default = "us-central1"
}
variable "zone" {
  type    = string
  default = "us-central1-a"
}
variable "machine_type" {
  type    = string
  default = "e2-small"
}
variable "backup_bucket_name" { type = string }
variable "external_ip" {
  type        = bool
  default     = true
  description = "Outbound package/image access. Disable only with an existing egress path; public ingress remains restricted to IAP SSH. IPv4 has a separate charge."
}
resource "google_project_service" "required" {
  for_each           = toset(["compute.googleapis.com", "cloudkms.googleapis.com", "iap.googleapis.com", "storage.googleapis.com", "artifactregistry.googleapis.com"])
  service            = each.value
  disable_on_destroy = false
}
resource "google_compute_network" "toolbox" {
  name                    = var.name
  auto_create_subnetworks = false
  depends_on              = [google_project_service.required]
}
resource "google_compute_subnetwork" "toolbox" {
  name                     = var.name
  ip_cidr_range            = "10.41.0.0/24"
  network                  = google_compute_network.toolbox.id
  private_ip_google_access = true
}
resource "google_compute_firewall" "iap" {
  name          = "${var.name}-iap-ssh"
  network       = google_compute_network.toolbox.name
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["${var.name}-iap"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
resource "google_service_account" "runtime" {
  account_id   = "${var.name}-runtime"
  display_name = "Toolbox VM key wrapper and append-only backup upload"
}
resource "google_kms_key_ring" "toolbox" {
  name       = var.name
  location   = var.region
  depends_on = [google_project_service.required]
}
resource "google_kms_crypto_key" "credentials" {
  name            = "credential-envelope"
  key_ring        = google_kms_key_ring.toolbox.id
  rotation_period = "7776000s"
  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }
  lifecycle { prevent_destroy = true }
}
resource "google_kms_crypto_key_iam_member" "runtime" {
  crypto_key_id = google_kms_crypto_key.credentials.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.runtime.email}"
}
resource "google_storage_bucket" "backups" {
  name                        = var.backup_bucket_name
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  versioning { enabled = true }
  lifecycle_rule {
    condition { age = 90 }
    action { type = "Delete" }
  }
  lifecycle { prevent_destroy = true }
}
resource "google_storage_bucket_iam_member" "upload" {
  bucket = google_storage_bucket.backups.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.runtime.email}"
}
resource "google_compute_disk" "data" {
  name = "${var.name}-data"
  type = "pd-standard"
  size = 30
  lifecycle { prevent_destroy = true }
}
resource "google_compute_instance" "toolbox" {
  name                      = var.name
  machine_type              = var.machine_type
  deletion_protection       = true
  allow_stopping_for_update = true
  tags                      = ["${var.name}-iap"]
  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = 15
    }
  }
  attached_disk {
    source      = google_compute_disk.data.id
    device_name = "toolbox-data"
  }
  network_interface {
    subnetwork = google_compute_subnetwork.toolbox.id
    dynamic "access_config" {
      for_each = var.external_ip ? [1] : []
      content {}
    }
  }
  service_account {
    email  = google_service_account.runtime.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }
  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
    serial-port-enable     = "FALSE"
  }
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
  # Provisioning prepares the host only. No credentials or application code in metadata.
  metadata_startup_script = file("${path.module}/prepare-host.sh")
  depends_on              = [google_project_service.required]
}
output "instance" { value = google_compute_instance.toolbox.name }
output "kms_key" { value = google_kms_crypto_key.credentials.id }
output "backup_bucket" { value = google_storage_bucket.backups.name }

resource "google_artifact_registry_repository" "images" {
  location      = var.region
  repository_id = var.name
  format        = "DOCKER"
  depends_on    = [google_project_service.required]
}
resource "google_artifact_registry_repository_iam_member" "pull" {
  project    = var.project_id
  location   = var.region
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.runtime.email}"
}
output "project_id" { value = var.project_id }
output "zone" { value = var.zone }
output "image_repository" { value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}/toolbox" }
