# METADATA
# scope: package
# title: Entity names must follow Mendix naming conventions
# description: Entity names must be singular nouns in UpperCamelCase with no
#   underscores, abbreviations, or special characters. Generic placeholder names
#   such as "Entity1" are not allowed.
# authors:
#   - Your Name <your.email@example.com>
# custom:
#   category: Maintainability
#   rulename: EntityNamingConvention
#   severity: MEDIUM
#   rulenumber: 999_0020
#   remediation: Rename the entity to a meaningful singular noun in UpperCamelCase
#     (e.g. "CustomerOrder" instead of "customer_order" or "Entity1").
#   input: .*DomainModels\$DomainModel\.yaml
package app.mendix.entity_naming_convention

import rego.v1

annotation := rego.metadata.chain()[1].annotations

default allow := false

allow if count(errors) == 0

is_upper_camel_case(name) if {
  regex.match(`^[A-Z][A-Za-z0-9]+$`, name)
}

is_generic_name(name) if {
  regex.match(`^(New)?Entity\d*$`, name)
}

# Violation: not UpperCamelCase
errors contains error_message if {
  some entity in input.Entities
  not is_upper_camel_case(entity.Name)
  not is_generic_name(entity.Name)
  error_message := sprintf(
    "[%v, %v, %v] Entity '%v' is not in UpperCamelCase (no underscores, starts with uppercase, letters/digits only)",
    [
      annotation.custom.severity,
      annotation.custom.category,
      annotation.custom.rulenumber,
      entity.Name,
    ],
  )
}

# Violation: generic placeholder name
errors contains error_message if {
  some entity in input.Entities
  is_generic_name(entity.Name)
  error_message := sprintf(
    "[%v, %v, %v] Entity '%v' uses a generic placeholder name — rename it to a meaningful singular noun",
    [
      annotation.custom.severity,
      annotation.custom.category,
      annotation.custom.rulenumber,
      entity.Name,
    ],
  )
}
