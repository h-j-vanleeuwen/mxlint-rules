# METADATA
# scope: package
# title: Layouts and snippets must have the correct prefix
# description: Layout names must start with a prefix that reflects their target
#   device or purpose (Responsive_, Tablet_, Phone_, NativePhone_, Popup_, Atlas_).
#   Snippet names must start with SNIP_. Correct prefixes make the purpose of UI
#   building blocks immediately clear in the App Explorer.
# authors:
#   - Your Name <your.email@example.com>
# custom:
#   category: Maintainability
#   rulename: LayoutSnippetNamingConvention
#   severity: LOW
#   rulenumber: 999_0080
#   remediation: Add the correct prefix to the layout or snippet name
#     (e.g. "Responsive_Main", "Popup_Confirmation", "SNIP_CustomerCard").
#   input: .*Pages\$.*\.yaml
package app.mendix.layout_snippet_naming_convention

import rego.v1

annotation := rego.metadata.chain()[1].annotations

default allow := false

allow if count(errors) == 0

valid_layout_prefixes := {
  "Responsive_",
  "Tablet_",
  "Phone_",
  "NativePhone_",
  "Popup_",
  "Atlas_",
}

has_valid_layout_prefix(name) if {
  some prefix in valid_layout_prefixes
  startswith(name, prefix)
}

# Violation: layout does not have a recognised prefix
errors contains error_message if {
  some layout in input.Layouts
  not has_valid_layout_prefix(layout.Name)
  error_message := sprintf(
    "[%v, %v, %v] Layout '%v' does not start with a recognised prefix. Expected one of: Responsive_, Tablet_, Phone_, NativePhone_, Popup_, Atlas_",
    [
      annotation.custom.severity,
      annotation.custom.category,
      annotation.custom.rulenumber,
      layout.Name,
    ],
  )
}

# Violation: snippet does not start with SNIP_
errors contains error_message if {
  some snippet in input.Snippets
  not startswith(snippet.Name, "SNIP_")
  error_message := sprintf(
    "[%v, %v, %v] Snippet '%v' must start with 'SNIP_' (e.g. 'SNIP_CustomerCard')",
    [
      annotation.custom.severity,
      annotation.custom.category,
      annotation.custom.rulenumber,
      snippet.Name,
    ],
  )
}
