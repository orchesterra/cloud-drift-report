variable "filename" { type = string }
variable "content" {
  type    = string
  default = "hello"
}

resource "random_pet" "name" {}

resource "local_file" "out" {
  filename = var.filename
  content  = "${var.content} ${random_pet.name.id}"
}

output "id" { value = random_pet.name.id }
