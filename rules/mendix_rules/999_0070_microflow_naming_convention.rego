# METADATA
# scope: package
# title: Microflows must have the correct prefix based on their trigger type
# description: Microflow names must start with a recognised prefix that reflects
#   their trigger or purpose (e.g. ACT_, DS_, SUB_, VAL_, SCE_, BCO_, ACO_).
#   This makes the role of a microflow immediately clear without opening it.
# authors:
#   - Your Name <your.email@example.com>
# custom:
#   category: Maintainability
#   rulename: MicroflowNamingConvention
#   severity: MEDIUM
#   rulenumber: 999_0070
#   remediation: Add the correct prefix to the microflow name based on its trigger
#     type (e.g. "ACT_Order_Submit", "DS_Customer_GetActive", "VAL_Invoice_Check").
#   input: .*Microflows\$.*\.yaml
package app.mendix.microflow_naming_convention

import rego.v1

annotation := rego.metadata.chain()[1].annotations

default allow := false

allow if count(errors) == 0

# All recognised prefixes from the Mendix naming conventions.
valid_prefixes := {
  "ACT_",  # Action button
  "IVK_",  # Action button (legacy)
  "DS_",   # Data source
  "OEN_",  # On enter event
  "OCH_",  # On change event
  "OLE_",  # On leave event
  "BCO_",  # Before commit
  "ACO_",  # After commit
  "BCR_",  # Before create
  "ACR_",  # After create
  "BDE_",  # Before delete
  "ADE_",  # After delete
  "BRO_",  # Before rollback
  "ARO_",  # After rollback
  "CAL_",  # Calculated attribute
  "VAL_",  # Validation
  "SCE_",  # Scheduled event
  "SUB_",  # Sub-microflow
  "ASU_",  # After startup sub
  "BSD_",  # Before shutdown sub
  "HCH_",  # Health check sub
  "WFA_",  # Workflow user assignment
  "WFS_",  # Workflow system action
  "WFC_",  # Workflow on created
  "CWS_",  # Consumed web service
  "CRS_",  # Consumed REST service
  "PWS_",  # Published web service
  "PRS_",  # Published REST service
  "POS_",  # Published OData service
  "TEST_", # Unit test
  "UT_",   # Unit test (alternative)
}

# Well-known fixed microflow names that do not use a prefix by convention.
fixed_names := {"AfterStartUp", "BeforeShutDown", "HealthCheck"}

has_valid_prefix(name) if {
  some prefix in valid_prefixes
  startswith(name, prefix)
}

is_fixed_name(name) if {
  name in fixed_names
}

errors contains error_message if {
  some microflow in input.Microflows
  not has_valid_prefix(microflow.Name)
  not is_fixed_name(microflow.Name)
  error_message := sprintf(
    "[%v, %v, %v] Microflow '%v' does not start with a recognised prefix (e.g. ACT_, DS_, SUB_, VAL_, BCO_, ACO_)",
    [
      annotation.custom.severity,
      annotation.custom.category,
      annotation.custom.rulenumber,
      microflow.Name,
    ],
  )
}
