package ldif

import (
	"strings"
	"testing"
)

var PEMCerts []string = []string{
	`-----BEGIN CERTIFICATE-----
MIIGTjCCBDagAwIBAgIQOFGcgEofbpFK8jifxQuE1jANBgkqhkiG9w0BAQsFADBC
MQswCQYDVQQGEwJCVzEMMAoGA1UEChMDR09WMRIwEAYDVQQLEwlNTklHQS1ESUMx
ETAPBgNVBAMTCENTQ0EtQldBMB4XDTE4MTEyMzEzMTgwMVoXDTMyMTEyMzEzMjc1
MFowQjELMAkGA1UEBhMCQlcxDDAKBgNVBAoTA0dPVjESMBAGA1UECxMJTU5JR0Et
RElDMREwDwYDVQQDEwhDU0NBLUJXQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBALJuau0gSxwZNpsa2AFSEJs8hP9tjKt33/gsPs+79kFjknPeOAr5PpXL
nWzmrE0Knuhulld9WC9V6KUDsucMB5nkrnE6wBlfSWSn62ovyFyvHZc7HqQArGQI
j0Ktq256jpyU/9tqNF7BgooFYLLeREsbNaeowpST/gpsytAjVxVHcJdRz/97ooVy
0GrRvAoV3Eu/Ztvu3kbrYXvkcVY/CoIyxl2rmcI48Tk/6M9FynQugnQXuZbYUXJp
6SK9FTEky1mw7L1tfRiQeOJbnI6n/b054fDkgmGVeXOgwg8PyWMmTZfHC7gth4G0
biNd952KPf3ZU+R3kWg/RGsc3m24zNN1SJiw+A7dyfc1pMAAL/KPvy5JWWtIENjg
1B2nVRrYNGC3MKWsh384e+dy30wJPYYIK3tvEYk1xPwahaqAMD7ENnHZ+VmZuBQp
6HVaNdySMLOXFgXuSsLbeIPpc5QA89jTYL54Qf39V6u/SnG7XJ+glTPVztsTVPYw
YurxEsaUEKBeU2ulMS8b/uarSp0LdvNdz8nsMi4gsdg5pag8T0mfLJq/jbJSV7E5
kaRybFxwUz77z5+8llVaiU65Bh4TQaheecL9JOASDM8+VN/nRIvRgR1v+amEx9WW
5Sts7XCrLLWnz8w5/BXoedaoC+M6g5zm/IcsFXZEYAppTfxf8bexAgMBAAGjggE+
MIIBOjAOBgNVHQ8BAf8EBAMCAQYwKwYDVR0QBCQwIoAPMjAxODExMjMwMDAwMDBa
gQ8yMDIxMTEyMzAwMDAwMFowGwYDVR0RBBQwEqQQMA4xDDAKBgNVBAcMA0JXQTAb
BgNVHRIEFDASpBAwDjEMMAoGA1UEBwwDQldBMGcGA1UdHwRgMF4wXKBaoFiGKmh0
dHBzOi8vcGtkZG93bmxvYWQxLmljYW8uaW50L0NSTHMvQldBLmNybIYqaHR0cHM6
Ly9wa2Rkb3dubG9hZDIuaWNhby5pbnQvQ1JMcy9CV0EuY3JsMBMGCSsGAQQBgjcU
AgQGHgQAQwBBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOifut3L/ghy
yyT+cvdEt5A3G/48MBAGCSsGAQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBCwUAA4IC
AQAinC+VkYXo3NxGeW6DQVUJNI9CUGZqpxDUpP36wAcEfLf0NTT/Q/tcOxmNBU17
jxga9dGE0bVnS59pNTNBJCpb/jw8CJxk6lSOa0iZcCTdjJk873IOA9BBaa0rXfGy
/ipQBizqUehAbBedcHs+EJ4CAfep7nvxwaN6Hyq8wPLtEYEaZ1bCAgFxKCkDFrJz
WCFAlDBJfNkzMO5MfOasfKFCMcFZHLooY2jJEUTRE7AS5WMTMapwrpHnyqVEss/1
83cU3ZjCx7tT26glYH+Je4OBCxcCjMADTyzsV42Dlm8xjUiQ9YBLBdfgqPkG7Jpl
AkCS4QYmTlClG9R5JdIk8RC3wEj+LkxGgZEaIcG0lwBER7siBpqYvxl8x58tqXHp
A4v3tdZERol+UTCPS+DhtHH/SX6ravZBwimlaE8ucU44EFGnynOwnUnh9uQJSTB+
E2ui99sPolC3YEm4Zdwc+zPicE1ciy4vqQ//LXNj6MTIjAJhMqvp56WZca1Wr5w8
or1SbWQIVNvpInIwJJUnYnh9tt5KR4rOdHQHmGfiBnIotTAeb3KAcO5MwqsxxAQ1
zghGlkXmJpSI/O+COpWu/mvfBnnglcnts1W40/xtzS6lovrA08PdR31yAj+ODhwB
yQdMRO4jOvWGQAkrGHDC+jJAk+C+t7MyPfZH5Vf+fLPM9g==
-----END CERTIFICATE-----
`,
	`-----BEGIN CERTIFICATE-----
MIIFeDCCA2CgAwIBAgIQBMZIPFMa/oFBkNcCnJprMTANBgkqhkiG9w0BAQsFADBB
MREwDwYDVQQLEwhNTEhBLURJQzEMMAoGA1UEChMDR09WMQswCQYDVQQGEwJCVzER
MA8GA1UEAxMIQ1NDQS1CV0EwHhcNMDkwOTE1MDc1MjQyWhcNMjkwOTE1MDgwMTE1
WjBBMREwDwYDVQQLEwhNTEhBLURJQzEMMAoGA1UEChMDR09WMQswCQYDVQQGEwJC
VzERMA8GA1UEAxMIQ1NDQS1CV0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQCqrKmBNRKHHR47xpX8ArsQxLkzSP+oA1dnbwmbkohYEuaABB3Oy3uchZv1
H/i7oovrJIKxkx9k4l73urlyKqn2xIZd/Ci+Uj2jDIBaCMAPm/bbOa8deIfnpPsG
DZy9cT08K0eFyAK9yFZs68penXqjxgOZ2fy4SNCOjymgYGkXCBrDo+aquhzeWkSF
WwNuNl5lMVo+7iAa52M+xcnN88O7DN/7VkTvcfGtEFAC08U0L655yqAZF0bl+AEF
laLwtTG+S89FXW0dc7E4a73WAvZYn24kgRj49mCMe9zzS6EyQM/ul2qgiDwisUFT
iGDS79ZkIXj2mceXW+n7Tl7vWCEKzYGG3XAw2w/QtzXLy2GdaByXV/yZ/96FH4tO
ITjA+nyYAn7AfX1TqYvzMS+OgXJQKh/AREY4yAmJFcC130sKvwOwAoXRkTkvzmWS
Tzv7jRw9oqplqgUwW1GWS1JxecvbYXatuW2TPs97VIMpS3leqMFgmuX8pDzE3scp
UdsDJEJrc11RtN46E6zKg5vk9u2+KZkcgq2PEOQecy3VihzcqGk6PayLfum2lGSN
vE4DTz2GpPwF+vPhRBop0HxvqeSkqzi+YUrrVXdkOIXTgf8/6ghFzd6Dux3e2tDY
QJqDKJmfZDs6BB8VL/+ZtfvxdkHvjxK9u7t9hXF2LayBdT91cwIDAQABo2wwajAO
BgNVHQ8BAf8EBAMCAQYwEwYJKwYBBAGCNxQCBAYeBABDAEEwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUbfHPhBy4UzOi6uqn6nYRHAJXkewwEAYJKwYBBAGC
NxUBBAMCAQAwDQYJKoZIhvcNAQELBQADggIBAJL0ZUEw4jgf9q1M9h+YyQd05S7E
RXX5rL/LaBo3xF5AkCPeA2fYXcoqBnLkzRMU+BHkzOnWRW3D1mov/Kt91WAWx+5n
9Lyy71s3myPdc/cUXe9uuZ+7jBKtTA8AafRQpuIkrKixF47ax5IN7DP/ihbHdgL+
i5fkuuszIcHOTGY7QUk7Hp2ME89EJAAVzSTrw0BmarPxwnKSUhW+xRluMrL/+gSS
dZyuW8M1RYsAqlJMmWkxzKP2HPulXNL/fne0U5JPPUMgvB7C4ulFkkRsHL3wlJ4E
+nNKUxQBwIG1X4IkyGq3JSRAaeY2j8qKGXtHZz6BBcnoFm0YBuqIaA8kTRsWBU4H
iTt/mucG0yDZAu9MOO8csp0XKLxKrvGS7AQoGVKhJIo9iP4o0jgNUeADT7P/yr3T
Bp/tp6cpXaGbEXQDP2ITuoWE59R1N18ARFPpW/0edUGcvvtuB7B1xh+oKQ4lEWt3
sp8+HZgpYcWpdzeQgnb17eUkzhoaw8uZA5NkHzDDuNPzYg0v5F51/gcC7FY8E8pl
qPxmLNKYhVUvO71b/3oxdQGt+KyCfhm2mTNsMxTPYwJP0XwleMVHGnX3xSDLNkSY
IWfhHiU5rQ78P1wo1PWcuUS+tkOg6yIjArNHLo4qYVpTXdHuqAyBt4u9WdwFMuxX
N2PXu5CQFbYW2uTd
-----END CERTIFICATE-----
`,
}

var ldifData string = `dn: c=BW,dc=data,dc=download,dc=pkd,dc=icao,dc=int
objectClass: top
objectClass: country
c: BW

dn: o=ml,c=BW,dc=data,dc=download,dc=pkd,dc=icao,dc=int
objectClass: top
objectClass: organization
o: ml

dn: cn=CN\=CSCA-BWA\,OU\=MNIGA-DIC\,O\=GOV\,C\=BW,o=ml,c=BW,dc=data,dc=downl
 oad,dc=pkd,dc=icao,dc=int
pkdVersion: 119
sn: 1
cn: CN=CSCA-BWA,OU=MNIGA-DIC,O=GOV,C=BW
objectClass: top
objectClass: person
objectClass: pkdMasterList
objectClass: pkdDownload
pkdMasterListContent:: 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

`

var ldifData2 string = `dn: c=FI,dc=data,dc=download,dc=pkd,dc=icao,dc=int
objectClass: top
objectClass: country
c: FI

dn: o=ml,c=FI,dc=data,dc=download,dc=pkd,dc=icao,dc=int
objectClass: top
objectClass: organization
o: ml

dn: cn=CN\=CSCA Finland\,OU\=VRK\,O\=Finland\,C\=FI,o=ml,c=FI,dc=data,dc=dow
 nload,dc=pkd,dc=icao,dc=int
pkdVersion: 153
sn: 1
cn: CN=CSCA Finland,OU=VRK,O=Finland,C=FI
objectClass: top
objectClass: person
objectClass: pkdMasterList
objectClass: pkdDownload
pkdMasterListContent:: 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
 fuySOnRIoeEmuJuPsfuKo1U+kX+Y2y6c+BrXZZ0zMW2g9KgidMOdxpJFL1EzGiMRuKc04H0mn2L
 mwtCgdDtHm7ldzJ2mZf61Eg6hKLUZSuFJkLlv+gPDzUVxxIj6ZNyYmO0WUz/h8NviqLhjHNPFlw
 SBHyrVvwc+g1zrecAQFKLAogHKT5a46sbZzxCZVgRLjOkt6R+MxG/+CFG6wi9CKyvODxExrnfHM
 x2kBrnwc0fmIQ3HnYlwMSHDaxdcR6gfm38SXGDg2u9ffrAQCHXHuuMylFMPzQBSj03fxr8Yiepn
 8Ozvl+0B2wVC0MIHdBA+7Fxh/cGJTRB5DZenPg/h0na5sY675PqsgtPwARWn6FGIcCr3ZB9j/Tv
 8pCbxVzqvDnbM0jpNZzuon/vaLXXjbB9nVr1c7VgxIMr1ni/3zZhmw64Vx/MJ9ifvB0mVfRsqdG
 eW0EEwnRjO7TWi4jJuuHRbfLoQMVUixcxHRXB/rRikpWLztmx5MnQmOyAA4+1F2vLCV9Dw1uyM4
 /NxoyA6m9p7QQEuScYBwky4Mg3beNvuusv4M1pwpjBFCCy2qGNvT6OomkGfMp5SCVlvXV31oGBY
 KN5jabWq9W3hPA/wIDAQABo4IBkjCCAY4wHwYDVR0jBBgwFoAUmllLW/kpep192amnIVS4WQDSR
 kIwHQYDVR0OBBYEFJpZS1v5KXqdfdmppyFUuFkA0kZCMA4GA1UdDwEB/wQEAwIBBjArBgNVHRAE
 JDAigA8yMDE2MDEyOTA4MDY1MFqBDzIwMjEwMTI5MDgwNjUwWjAVBgNVHSAEDjAMMAoGCCqBdoQ
 FAgoFMFQGA1UdEgRNMEukEDAOMQwwCgYDVQQHDANGSU6BGENTQ0EuRmlubGFuZEBpbnRlcm1pbi
 5maYYdaHR0cDovL3d3dy5wb2xpaXNpLmZpL2VuL2NzY2EwVAYDVR0RBE0wS6QQMA4xDDAKBgNVB
 AcMA0ZJToEYQ1NDQS5GaW5sYW5kQGludGVybWluLmZphh1odHRwOi8vd3d3LnBvbGlpc2kuZmkv
 ZW4vY3NjYTASBgNVHRMBAf8ECDAGAQH/AgEAMDgGA1UdHwQxMC8wLaAroCmGJ2h0dHA6Ly9wcm9
 4eS5maW5laWQuZmkvY3JsL2NzY2FmaW5jLmNybDANBgkqhkiG9w0BAQsFAAOCAgEApI6F7XLkgr
 kKyVAALsj38EfkiA3/RmHH4fASjXiqKjbiT+TIAxLcRiruCYv2qo7b7Dk9heGrY6pC8ksZZl0iG
 0cJykW9FGgj4FwDO2Om5qjpaIC0Ng7Pb9jVnIJwhlzCyXtIJpEDOfoGQpRDjJLeRdgXll39CUwv
 rhG1U4FgTQJ/TuaLGHD17p/VQoG097gWWraQaUdXgL+GJxDsvPWIg6N+LHkJmHRnzwC3CmaLlX1
 4ml9FqATZ46Xf4gp65l7ad2Zkc+I4+IbGyjLn9hbBcdSIyRGnCi0YJbEI6xC6W2rgvmemq0/pN5
 EqGYWb0Cfza5KlakxnIxPTVjYGAgdd3oBWEuMLWzpc3kwne34Ps9vttg0sujkjVvpaD7VGOY76q
 frQs1yfVR65HmltTGa/3w8LyzmsvwtihqXfuRASgneF9YT5hxp19VZQr0MfMj45mI3FNZJqQbR0
 UWSJWvXymLm+SVytZ0DgYTxTE2x3virTi8wmTEg2AlozxIsFeUrjcUbBA35N+mkWQEPBcrYNSMG
 lEJ1bbSNCFo3QTOA0Fv+3C1fbpOda8BeCl78zuGhiGzMLitDGfazeZewYST2sp/oB431mdLr7P2
 0ew/pDig4esRC070MVtfPplTzbKrZF/A+7gBYoLqHg+KynQ8zSQz+CEZmgkj0LgCZpBe11gHIwg
 gaaMIIEgqADAgECAgQAm6RyMA0GCSqGSIb3DQEBCwUAMEQxCzAJBgNVBAYTAkZJMRAwDgYDVQQK
 DAdGaW5sYW5kMQwwCgYDVQQLDANWUksxFTATBgNVBAMMDENTQ0EgRmlubGFuZDAeFw0yMDA3MTY
 wNzQ5MTNaFw0yNjA0MjYwODA2NTBaMEQxCzAJBgNVBAYTAkZJMRAwDgYDVQQKDAdGaW5sYW5kMQ
 wwCgYDVQQLDANWUksxFTATBgNVBAMMDENTQ0EgRmlubGFuZDCCAiIwDQYJKoZIhvcNAQEBBQADg
 gIPADCCAgoCggIBAIRB1+dCnMCXi8n8XAMo7gMz5zgsOtBozPeFR72v7N7oBEQt2o4qgbKem1RZ
 pcikipzQW5TldWbdqamfsqNOgpRnlo+eD2+XwdDCsyBiOgLhnZASbhbMA3zgAZA81SX+ggyAWzz
 y8pBotUTfGvFkyJa2RmwkVDHij1/59Hx0yMfuKXwMx82lkojZjk6aTsamZZLxQLLTnh8BgsQQmV
 LkG97BwXjvRPno7k0jA0MPCPLwV9MEQdsZoWQBMo5LopgEH4+JfZlIfxxhRzNc7HcCMuWaj+s3K
 Wd6QFUgrv++zWaNw3Of1bgVecIdDwYEecRhThGK8P41a+t2jDUnmUB4wVT8G5mp7CcaOTu1M4q0
 iBUMnWMcyeP2agTbFueptDO41ih6gzxYelw3eh6MfRXWJGWkObSB2XNsWfpc11+NI0Nr+YeI4sY
 gSYkdUUO2ZP3dUS6JQhbPmOUGNs9DRCgSc6eq39KjjnELyI23Zdry8iMCt43VOz/FrwrZUh3dWr
 icRVIxgaiYpBwYGAWSc774VzjFmRMlS0MSzteoMf6SgEJPWNhx7yKOoYEnMXBZOPzRVFM5YsAyk
 fTzh+oPyLnpQYXAXF5BJtH26vPAnrOpW6opdlHh8Hxvw8W2aRL5yejcyIJvReBQKuMWONcBUG+8
 Ce3xP9/Y9Tq+B+4FzlYREY4pAgMBAAGjggGSMIIBjjAfBgNVHSMEGDAWgBSaWUtb+Sl6nX3Zqac
 hVLhZANJGQjAdBgNVHQ4EFgQUh1icKdl2nPW36mYaPIyl/KJovpQwDgYDVR0PAQH/BAQDAgEGMC
 sGA1UdEAQkMCKADzIwMjAwNzE2MDc0OTEzWoEPMjAyNTA3MTYwNzQ5MTNaMBUGA1UdIAQOMAwwC
 gYIKoF2hAUCCgUwVAYDVR0SBE0wS6QQMA4xDDAKBgNVBAcMA0ZJToEYQ1NDQS5GaW5sYW5kQGlu
 dGVybWluLmZphh1odHRwOi8vd3d3LnBvbGlpc2kuZmkvZW4vY3NjYTBUBgNVHREETTBLpBAwDjE
 MMAoGA1UEBwwDRklOgRhDU0NBLkZpbmxhbmRAaW50ZXJtaW4uZmmGHWh0dHA6Ly93d3cucG9saW
 lzaS5maS9lbi9jc2NhMBIGA1UdEwEB/wQIMAYBAf8CAQAwOAYDVR0fBDEwLzAtoCugKYYnaHR0c
 DovL3Byb3h5LmZpbmVpZC5maS9jcmwvY3NjYWZpbmMuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQAS
 I+vjIzlDOse80bg62yHSzf05Q/+WMnSJfr6iCj+ynSc9nk52VhWUcpi2Ziuefzx0qZA+oFzTz6m
 dRN/64XfayECr5bOjOuscuTJPWM3Pyc9RJk+6c7BNEkFLA+bxfjKW2x8P/uTSl88v91CeoNa+Kw
 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
 H2dWvVztWDEgyvWeL/fNmGbDrhXH8wn2J+8HSZV9Gyp0Z5bQQTCdGM7tNaLiMm64dFt8uhAxVSL
 FzEdFcH+tGKSlYvO2bHkydCY7IADj7UXa8sJX0PDW7Izj83GjIDqb2ntBAS5JxgHCTLgyDdt42+
 66y/gzWnCmMEUILLaoY29Po6iaQZ8ynlIJWW9dXfWgYFgo3mNptar1beE8D/AgMBAAGjggGgMII
 BnDAfBgNVHSMEGDAWgBREmAZI4fn9fG24K2s1PAnPJvKQJjAdBgNVHQ4EFgQUmllLW/kpep192a
 mnIVS4WQDSRkIwDgYDVR0PAQH/BAQDAgEGMCsGA1UdEAQkMCKADzIwMTYwMTI5MDgwNjUwWoEPM
 jAyMTAxMjkwODA2NTBaMFQGA1UdEQRNMEukEDAOMQwwCgYDVQQHDANGSU6BGENTQ0EuRmlubGFu
 ZEBpbnRlcm1pbi5maYYdaHR0cDovL3d3dy5wb2xpaXNpLmZpL2VuL2NzY2EwgbcGA1UdHwSBrzC
 BrDAroCmgJ4YlaHR0cDovL3Byb3h5LmZpbmVpZC5maS9jcmwvZmNjYWMyLmNybDB9oHugeYZ3bG
 RhcDovL2xkYXAuZmluZWlkLmZpOjM4OS9jbiUzZEZpbmxhbmQlMjBDb3VudHJ5JTIwQ0ElMjAyL
 G91JTNkVlJLLE8lM2RTdW9taSUyMEZpbmxhbmQsQyUzZEZJP2NlcnRpZmljYXRlUmV2b2NhdGlv
 bkxpc3QwDQYHZ4EIAQEGAQQCBQAwDQYJKoZIhvcNAQELBQADggIBACV44MiTSATlVckHdyPBVXk
 H8pClOKz17rSCCqpzVFUhFULj6nstUKcDmL/rTNd5LoGVS2eTrnzLIf7WH4KBQHsq+Tmfoe170y
 J0w5l+51NXB3LNBMDO8EtN9sF5ABW7iwC7l1GfpJOMr78WeWBrz16EiAX8DPxXAlWuNNFZ0ftO8
 wYRywkDCKOwY6jvy7Hkek3C894QXB54egmI41docqo8riQKWhRQsdSyMBz6+EtQJKprcbhCnIYS
 jMVcP2Ui+9ahLpbePuKN2mOUWT8W0zINg6sj4XmP9EO73DJYmrNtbWpBt6hmemrj7AU8nQeDvOt
 2Ui2ZMziHnqwghFMb+ZRg4GsC1macqVhcdTn51viKNjepJUyzVd3VxXAed4rGoADaK8RG1+eJRE
 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
 k5em3cWEY+QeT0K/ObBp/Wv4mhBnKg==

`

func TestLDIFToPEM1(t *testing.T) {
	data, err := LDIFToPEMReader(strings.NewReader(ldifData))
	if err != nil {
		panic(err)
	}

	for _, entry := range data {
		if entry == PEMCerts[0] || entry == PEMCerts[1] {
			continue
		}

		t.Fatalf("certificates doesn't equal")
	}
}

func TestLDIFToPEM2(t *testing.T) {
	data, err := LDIFToPEMReader(strings.NewReader(ldifData2))
	if err != nil {
		panic(err)
	}

	for _, entry := range data {
		if entry == PEMCerts[0] || entry == PEMCerts[1] {
			t.Fatalf("certificates equal")
		}
	}
}