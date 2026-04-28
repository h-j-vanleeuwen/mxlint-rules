# METADATA
# scope: package
# title: Module names must follow Mendix naming conventions
# description: Module names should be in UpperCamelCase and must not contain
#   underscores, spaces, or special characters. A module should reflect its
#   responsibility, e.g. CustomerManagement or SharePointIntegration.
# authors:
#   - Your Name <your.email@example.com>
# custom:
#   category: Maintainability
#   rulename: ModuleNamingConvention
#   severity: MEDIUM
#   rulenumber: 999_0010
#   remediation: Rename the module to UpperCamelCase that clearly identifies
#     its responsibility (e.g. "CustomerManagement" instead of "customer_management").
#   input: .*Settings\$AppSettings\.yaml
package app.mendix.module_naming_convention

import rego.v1

annotation := rego.metadata.chain()[1].annotations

default allow := false

allow if count(errors) == 0

# UpperCamelCase: starts with uppercase, only letters and digits, no underscores.
is_upper_camel_case(name) if {
  regex.match(`^[A-Z][A-Za-z0-9]+$`, name)
}

errors contains error_message if {
  some module in input.Modules
  not is_upper_camel_case(module.Name)
  error_message := sprintf(
    "[%v, %v, %v] Module '%v' is not in UpperCamelCase (no underscores, starts with uppercase, letters/digits only)",
    [
      annotation.custom.severity,
      annotation.custom.category,
      annotation.custom.rulenumber,
      module.Name,
    ],
  )
}
