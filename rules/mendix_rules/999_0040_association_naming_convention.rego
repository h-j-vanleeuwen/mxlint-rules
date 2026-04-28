# METADATA
# scope: package
# title: Multiple associations between the same entities must have a descriptive suffix
# description: When multiple associations exist between the same two entities, each
#   association name must be extended with a recognizable purpose suffix following
#   the pattern Entity_Entity_Purpose. Auto-generated single associations are exempt.
# authors:
#   - Your Name <your.email@example.com>
# custom:
#   category: Maintainability
#   rulename: AssociationNamingConvention
#   severity: LOW
#   rulenumber: 999_0040
#   remediation: Extend the association name with a purpose suffix,
#     e.g. "Person_Address_Delivery" or "Person_Address_Postal".
#   input: .*DomainModels\$DomainModel\.yaml
package app.mendix.association_naming_convention

import rego.v1

annotation := rego.metadata.chain()[1].annotations

default allow := false

allow if count(errors) == 0

# Build a key from the two entity names in the association (order-normalised).
association_pair_key(assoc) := key if {
  parts := [assoc.Parent, assoc.Child]
  sorted := sort(parts)
  key := concat("_", sorted)
}

# Group association names by their entity pair.
associations_by_pair[pair_key] contains assoc.Name if {
  some assoc in input.Associations
  pair_key := association_pair_key(assoc)
}

# Violation: more than one association between the same pair but name has no
# purpose suffix (i.e. name matches only Entity_Entity without a third segment).
errors contains error_message if {
  some assoc in input.Associations
  pair_key := association_pair_key(assoc)
  count(associations_by_pair[pair_key]) > 1
  parts := split(assoc.Name, "_")
  count(parts) < 3
  error_message := sprintf(
    "[%v, %v, %v] Association '%v' — multiple associations exist between '%v' and '%v'; extend the name with a purpose suffix (e.g. '%v_Purpose')",
    [
      annotation.custom.severity,
      annotation.custom.category,
      annotation.custom.rulenumber,
      assoc.Name,
      assoc.Parent,
      assoc.Child,
      assoc.Name,
    ],
  )
}
