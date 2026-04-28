# METADATA
# scope: package
# title: Enumerations must have the ENUM_ prefix
# description: All enumerations must be prefixed with ENUM_ to make them easily
#   identifiable across the domain model, microflows, and pages. The name after
#   the prefix should be in UpperCamelCase and reflect the business context,
#   e.g. ENUM_ShippingStatus.
# authors:
#   - Your Name <your.email@example.com>
# custom:
#   category: Maintainability
#   rulename: EnumerationNamingConvention
#   severity: LOW
#   rulenumber: 999_0050
#   remediation: Rename the enumeration to follow the pattern ENUM_{BusinessContext}
#     in UpperCamelCase (e.g. "ENUM_ShippingStatus").
#   input: .*DomainModels\$DomainModel\.yaml
package app.mendix.enumeration_naming_convention

import rego.v1

annotation := rego.metadata.chain()[1].annotations

default allow := false

allow if count(errors) == 0

# Valid: ENUM_ prefix followed by UpperCamelCase business context name.
is_valid_enum_name(name) if {
  regex.match(`^ENUM_[A-Z][A-Za-z0-9]+$`, name)
}

errors contains error_message if {
  some enumeration in input.Enumerations
  not is_valid_enum_name(enumeration.Name)
  error_message := sprintf(
    "[%v, %v, %v] Enumeration '%v' does not follow the pattern ENUM_{BusinessContext} (e.g. 'ENUM_ShippingStatus')",
    [
      annotation.custom.severity,
      annotation.custom.category,
      annotation.custom.rulenumber,
      enumeration.Name,
    ],
  )
}
