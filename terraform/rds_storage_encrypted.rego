package main

########here-bitbark-os

module_address[i] = address {
	changeset := input.resource_changes[i]
	address := changeset.address
}

type(resource, elem) {
	resource.type == elem
}

action(resource, elem) {
	resource.change.actions[_] == elem
}

allowed_storage_encrypted(rsrc) = "false" {
	rsrc.change.after.storage_encrypted == false
} else = "true" {
	rsrc.change.after.storage_encrypted == true
}

encrypted_false[i] = msj {
	rsrc := input.resource_changes[i]
	rlist := resource_whitelist.security_storage_encrypted_false
	not list_contains_value(rlist, rsrc.name)
	type(rsrc, "aws_db_instance")
	action(rsrc, "create")
	storage_encrypted := rsrc.change.after.storage_encrypted
	storage_encrypted == false
	message := {"allowed": allowed_storage_encrypted(rsrc), "branch": object.get(opa.runtime().env, "CI_COMMIT_REF_NAME", "empty"), "project_url": object.get(opa.runtime().env, "CI_PROJECT_URL", "empty"), "pipeline_id": object.get(opa.runtime().env, "CI_PIPELINE_ID", "empty"), "commit_id": object.get(opa.runtime().env, "CI_COMMIT_SHA", "empty"), "opa_rule_name": "storage_encrypted_false", "resource_name": rsrc.name, "resource_type": rsrc.type, "storage_encrypted": json.marshal(rsrc.change.after.storage_encrypted), "actions": json.marshal(rsrc.change.actions)}
	msj := [message | available(json.marshal(message))]
}

deny[msg] {
	msjAux := encrypted_false[_]
	msg = sprintf("Error", msjAux)
}
