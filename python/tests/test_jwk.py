from minaombud.crypto.key import ParsedJwk


PEM_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1LYczt8dm+rW/RZabyUY
yQsxTA93qENwCKPSWz3vMApn9lO64UGERG83rshtS9hGbn+ebl5D7koodf+Faqwq
SwQPUEVFNLmF4Vfy1bVADvwWPEs3i+8lDuKqsPImghJaJdLLkz+aC/XffFzHQPyX
94S7oiLlAV3x+ox/wSqI+ShCtD6i61Uuvsi9ArcXE/eGvyZfGQwXfweTN8eE8Kdi
CbtN96IxbtvZisrNuxqhihOAwCD9UkAOJZYdwaugu2vjDnLNG+kWCB0U5+Kxy7Jd
SXdcQkhLg1UfoOQ3ZA7hVWT2LhEyvj61ns1VZb+f/hBVjJvKTCXxsdD2i6PvFlQJ
6QIDAQAB
-----END PUBLIC KEY-----
"""

PEM_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDUthzO3x2b6tb9
FlpvJRjJCzFMD3eoQ3AIo9JbPe8wCmf2U7rhQYREbzeuyG1L2EZuf55uXkPuSih1
/4VqrCpLBA9QRUU0uYXhV/LVtUAO/BY8SzeL7yUO4qqw8iaCElol0suTP5oL9d98
XMdA/Jf3hLuiIuUBXfH6jH/BKoj5KEK0PqLrVS6+yL0CtxcT94a/Jl8ZDBd/B5M3
x4Twp2IJu033ojFu29mKys27GqGKE4DAIP1SQA4llh3Bq6C7a+MOcs0b6RYIHRTn
4rHLsl1Jd1xCSEuDVR+g5DdkDuFVZPYuETK+PrWezVVlv5/+EFWMm8pMJfGx0PaL
o+8WVAnpAgMBAAECggEBAIWsQGRc4D2YkiyQPJq2RGIrT3qOCdNLNf+n+8ztGgAl
ufmZ2souIxHilqqXN+A+9NwCBS00vhnkrpKg1lYYBagI0BrQvVIJ+LGJVIiqk6wX
DV4soqakzbQSC9SRCFQbdl1ooBhUEtnLVPvRTkJvuoyI9GVK6oE2aZfbbXmV4mg4
mDFS9Ziuq51gg9YdxobX/tYpZjAwHqskoihheV0zuuftwHZDyhrMLw+qyR1liBSY
i5WzeGPaHJ4ZW+fgBFyq9tGmLc2e0DqEUZJu+hOTrC4TGX3t6eNL6TicMmJIuUkg
l0fJxrXFeZIH4xUsLcxAPTH4bl2YxAN+M1HPt2en+IECgYEA9VF6GHiRyJOQv2j+
Ox7Gfo8ELngNv0Wr4FGLvVqiWRzmTq78Ly2kcNY4olL7xhFnbKdHCSciXVE/ayjT
A33+nDIMlWVjY4BtsGccbwwGKo+T1Gx5sOSMwvssmBAa3eYTiS+U/nBPGPMSrcdp
8KcE4qegzwGY7KhE7J0w83LxDXkCgYEA3fkr/eXJOLSs4noOAy6kNSJG5gwiYpJi
0gDe6P316s+5rRQ47kEzxHPKUAEpzoKxyJXYfhPdlW270sgDNcKmNgSz8a+34QEA
ts1v+avziGac/VO83XVBexh3MFjZwQzoz3UD1MgwMuYP5F80cVWNfOnBqcH2fIxF
dxNYo4nhc/ECgYBMaAAbNxJQ4oUm2NC2ITO5n1myD3pYpJ6P01Yut9fw4Wtp/l5V
Y2XgLxicljQM0MbhtIgPdbziS7fw7FossEVo6L26mkWGbC29z5+vhpM1Flr4woB0
c/rTj9+nzPxROKPFCqjhRqGcJ7kdnwqEBcEjxwny75BtxUsSVzMz4AzsIQKBgC/w
gonBOOYgTz5ScfhJ+HjpQDqq4Do9t033liznvFbMKiOxPGJofo+tGkKRHcBWBaN2
iV0hWTfOjUQGonrX4SHFfj9yXdogZ1ETqV1Yv63zy3ACx8Vkb5HwRL2SUuUYrqcv
dHZeDdrQSRpfXWokufwCWCsbkupvOQlwijI3sxNhAoGAMFZqXfaUhDaPZTLLg46E
mcB2Ycd/ZsySD4PekVhYkgNZjQZQU+QIScY8I9UmQYoxZbavE1oJ7MoMKD2ztEKJ
26Qnezuul7L3YoIKx0AwhH/UQ8DahblvogDhYSHxwZiluHQOXwo7hvsFd0Hee7n9
Aq6XwLtO6zWtiixGTm6HDJk=
-----END PRIVATE KEY-----
"""

class TestParsePem:
    def test_rsa_public_key(self):
        key = ParsedJwk.from_pem(PEM_PUBLIC_KEY)
        assert key.kid == "3LD-ss8BVk7TDj3c4rWmRV74tlD8LlWTiZfLDPUpLrA"

    def test_rsa_private_key(self):
        key = ParsedJwk.from_pem(PEM_PRIVATE_KEY)
        assert key.kid == "3LD-ss8BVk7TDj3c4rWmRV74tlD8LlWTiZfLDPUpLrA"

    def test_rsa_key_pair(self):
        key = ParsedJwk.from_pem(PEM_PUBLIC_KEY + PEM_PRIVATE_KEY)
        assert key.kid == "3LD-ss8BVk7TDj3c4rWmRV74tlD8LlWTiZfLDPUpLrA"
        key = ParsedJwk.from_pem(PEM_PRIVATE_KEY + PEM_PUBLIC_KEY)
        assert key.kid == "3LD-ss8BVk7TDj3c4rWmRV74tlD8LlWTiZfLDPUpLrA"
