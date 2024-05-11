import asn1tools
foo = asn1tools.compile_files("./cert.asn1")
enc = foo.encode("Certificate",
    {
        "signature": bytes.fromhex("c3625638efe1f3066703e81b0439b767151850420385ffc172a0846920fd5ea00cdbadf4fc225fcda5c36954960c0532c2870046a6c4523c2a7b41894c59f305"),
        "details": {
            "name": "nas2",
            "ip": ('v4', {"address": bytes([192,168,5,1]), "suffix": 22}),
            "subnets": [
                ('v4', {"address": bytes([0,0,0,0]), "suffix": 1}),
                ('v4', {"address": bytes([128,0,0,0]), "suffix": 1}),
                ('v6', {"address": bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]), "suffix": 1}),
            ],
            "groups": ["default", "syncthing"],
            "notBefore": 1715295779,
            "notAfter": 1715295779,
            "publicKey": bytes.fromhex("68615a67fdf304812a3bb1662726d766aa5fb8700295f80e34a473e6d26d404e"),
            "issuer": bytes.fromhex("7eced9f5e1c0503e52d7811937ad1dd2ec70a07f7bb6c4d321d195a8736ef5e3")
        }
    }
)

print(enc.hex())