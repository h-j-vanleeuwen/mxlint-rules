# METADATA
# scope: package
# title: Attribute names must follow Mendix naming conventions
# description: Business attributes must be in UpperCamelCase with no underscores,
#   abbreviations, or special characters. Technical (non-business) attributes must
#   start with an underscore (_). Generic placeholder names such as "Attribute1"
#   are not allowed.
# authors:
#   - Your Name <your.email@example.com>
# custom:
#   category: Maintainability
#   rulename: AttributeNamingConvention
#   severity: MEDIUM
#   rulenumber: 999_0030
#   remediation: Rename business attributes to UpperCamelCase (e.g. "FirstName").
#     Prefix technical attributes with an underscore (e.g. "_SyncStatus").
#   input: .*DomainModels\$DomainModel\.yaml
package app.mendix.attribute_naming_convention

import rego.v1

annotation := rego.metadata.chain()[1].annotations

default allow := false

allow if count(errors) == 0

is_upper_camel_case(name) if {
  regex.match(`^[A-Z][A-Za-z0-9]+$`, name)
}

# Technical attributes: start with _ followed by UpperCamelCase
is_valid_technical_attribute(name) if {
  regex.match(`^_[A-Z][A-Za-z0-9]+$`, name)
}

is_generic_name(name) if {
  regex.match(`^(New)?Attribute\d*$`, name)
}

is_valid_name(name) if {
  is_upper_camel_case(name)
}

is_valid_name(name) if {
  is_valid_technical_attribute(name)
}

# Violation: not UpperCamelCase and not a valid technical attribute
errors contains error_message if {
  some entity in input.Entities
  some attribute in entity.Attributes
  not is_valid_name(attribute.Name)
  not is_generic_name(attribute.Name)
  error_message := sprintf(
    "[%v, %v, %v] %v.%v — attribute name must be UpperCamelCase or start with '_' for technical attributes",
    [
      annotation.custom.severity,
      annotation.custom.category,
      annotation.custom.rulenumber,
      entity.Name,
      attribute.Name,
    ],
  )
}

# Violation: generic placeholder name
errors contains error_message if {
  some entity in input.Entities
  some attribute in entity.Attributes
  is_generic_name(attribute.Name)
  error_message := sprintf(
    "[%v, %v, %v] %v.%v — attribute uses a generic placeholder name, rename it to a meaningful noun",
    [
      annotation.custom.severity,
      annotation.custom.category,
      annotation.custom.rulenumber,
      entity.Name,
      attribute.Name,
    ],
  )
}
