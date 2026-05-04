rule data_string_demo_secret {
  strings:
    $s = "MorphKatz_DataPass_OK_1234567890"
  condition:
    $s
}
