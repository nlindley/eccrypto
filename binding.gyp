{
  "targets": [
    {
      "target_name": "ecdh",
      "include_dirs": ["<!(node -e \"require('nan')\")"],
      "cflags": ["-Wall", "-O2"],
      "sources": ["ecdh.cc"],
    }
  ]
}
