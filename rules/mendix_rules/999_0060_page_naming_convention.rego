# METADATA
# scope: package
# title: Pages must have the correct suffix based on their purpose
# description: Page names must end with a recognised suffix that reflects their
#   purpose: _Overview, _New, _Edit, _NewEdit, _View, _Select, _MultiSelect,
#   _Tooltip, or _Workflow. This makes the purpose of a page immediately clear
#   from its name alone.
# authors:
#   - Your Name <your.email@example.com>
# custom:
#   category: Maintainability
#   rulename: PageNamingConvention
#   severity: LOW
#   rulenumber: 999_0060
#   remediation: Add the correct suffix to the page name based on its purpose,
#     e.g. "Customer_Overview", "Order_NewEdit", or "Product_Select".
#   input: .*Pages\$.*\.yaml
package app.mendix.page_naming_convention

import rego.v1

annotation := rego.metadata.chain()[1].annotations

default allow := false

allow if count(errors) == 0

valid_suffixes := {
  "_Overview",
  "_New",
  "_Edit",
  "_NewEdit",
  "_View",
  "_Select",
  "_MultiSelect",
  "_Tooltip",
  "_Workflow",
}

has_valid_suffix(name) if {
  some suffix in valid_suffixes
  endswith(name, suffix)
}

errors contains error_message if {
  some page in input.Pages
  not has_valid_suffix(page.Name)
  error_message := sprintf(
    "[%v, %v, %v] Page '%v' does not end with a recognised suffix. Expected one of: _Overview, _New, _Edit, _NewEdit, _View, _Select, _MultiSelect, _Tooltip, _Workflow",
    [
      annotation.custom.severity,
      annotation.custom.category,
      annotation.custom.rulenumber,
      page.Name,
    ],
  )
}
