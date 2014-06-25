rule the_rule {
 strings:
  $the = "the" nocase // Look for "the"

 condition:
  any of them
}
