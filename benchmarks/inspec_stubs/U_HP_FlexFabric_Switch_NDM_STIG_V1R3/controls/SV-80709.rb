control 'SV-80709' do
  title 'The HP FlexFabric Switch, when utilizing PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC. 

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA. 

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
  desc 'check', 'If PKI-based authentication is being used, determine if the HP FlexFabric Switch validates certificates by constructing a certification path to an accepted trust anchor.

[HP] display pki certificate domain HP local

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            3e:7b:9b:bb:00:00:00:00:00:28
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: DC=local, DC=rae-domain, CN=rae-domain-WIN2008-RAE-CA
        Validity
            Not Before: Apr 23 18:19:27 2015 GMT
            Not After : Apr 22 18:19:27 2016 GMT
        Subject: unstructuredAddress=15.252.76.101, C=US, ST=MA, L=Littleton, O=HP, OU=STG, CN=12508
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:e1:13:04:10:94:4a:a9:f7:6b:42:bb:64:13:4a:
                    eb:10:48:60:61:a5:e7:d6:13:95:2d:69:b0:79:ae:
                    df:be:e3:a2:5d:7d:be:3b:97:b9:2c:99:05:37:ea:
                    bf:a9:95:49:e7:08:50:14:68:fc:1d:16:83:f9:ea:
                    66:cc:8a:8f:f9:9c:28:dc:66:7a:80:0c:53:5e:cc:
                    a2:ee:4a:c3:4f:fb:6f:81:00:6c:4f:5d:72:e7:34:
                    dc:4c:06:18:97:7d:da:45:b5:f1:2b:7e:71:c7:62:
                    b3:59:fe:b9:6d:62:19:43:fd:73:93:fc:f5:ed:5e:
                    08:db:76:e7:66:26:cb:17:fd:69:a5:f5:b9:7e:e9:
                    9b:b4:91:30:d1:1a:1b:89:a3:ed:07:99:59:33:1e:
                    de:4d:96:34:67:8c:b2:20:4d:5f:ec:19:49:33:d6:
                    14:57:03:a5:90:9c:a7:6a:31:3f:37:c3:29:5b:0a:
                    db:24:2c:83:7d:e9:cb:c3:70:55:24:36:f5:c5:3f:
                    f5:4e:f5:87:05:99:2d:4a:59:6f:d9:2e:2d:90:c7:
                    fa:43:59:86:50:ee:e0:fc:2a:f9:bc:52:8c:39:d0:
                    05:3f:85:5c:5e:6b:5f:95:31:7b:e7:1e:b7:b5:af:
                    08:0d:34:8f:a0:07:4a:5a:32:eb:e7:39:5f:0e:9a:
                    f5:01
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Subject Alternative Name:
                IP Address:15.252.76.101
            X509v3 Subject Key Identifier:
                A7:B8:9F:0D:07:A9:31:91:ED:90:5C:F6:BF:6C:E0:7D:58:74:AB:08
            X509v3 Authority Key Identifier:
                keyid:07:8D:A0:CF:CB:47:DB:E3:BE:E9:F6:18:21:F6:19:05:B8:34:26:3E

            X509v3 CRL Distribution Points:

                Full Name:
                  URI:ldap:///CN=rae-domain-WIN2008-RAE-CA,CN=WIN2008-RAE,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=rae-domain,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint
            Authority Information Access:
                CA Issuers - URI:ldap:///CN=rae-domain-WIN2008-RAE-CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=rae-domain,DC=local?cACertificate?base?objectClass=certificationAuthority

            1.3.6.1.4.1.311.21.7:
                0,.$+.....7.....E...\\...
...0.............d...
            X509v3 Extended Key Usage:
                Code Signing
            1.3.6.1.4.1.311.21.10:
                0.0
..+.......
    Signature Algorithm: sha1WithRSAEncryption
        0b:1f:81:59:9d:4b:bf:b7:1c:a9:45:af:9e:2d:ab:0e:d4:a9:
        20:3b:f7:25:36:59:72:da:c9:80:3d:66:66:ab:4f:bf:d7:b4:
        55:23:96:24:2e:43:2c:20:79:41:d7:ec:23:18:55:49:d7:42:
        36:d3:0f:1f:99:50:c7:84:94:0f:6f:b0:b7:e7:6a:e7:e7:e0:
        d5:b8:09:f7:3d:1e:9b:6e:9e:7a:d8:39:30:66:60:f5:05:fd:
        d9:68:0d:22:73:7e:91:69:8c:a3:99:2f:24:a3:9b:96:a7:37:
        1d:a6:42:50:6d:8f:92:bf:90:8f:2b:26:a5:26:5c:59:f1:ef:
        12:1f:d3:77:8e:59:58:3c:c1:1c:20:74:31:95:2b:f2:71:69:
        39:fd:9b:06:4e:09:08:55:bc:ce:a7:3c:4e:1a:64:ae:0e:1b:
        a4:61:89:17:d1:72:31:20:2f:cc:24:97:d1:dd:1c:28:98:84:
        00:bc:3c:0e:c4:14:dd:26:6f:20:7d:0d:82:f7:71:d2:00:ec:
        1c:10:2e:35:a8:cc:75:0f:76:1b:7f:f2:d4:d9:df:a5:f8:c2:
        75:38:4c:7c:7f:42:81:a1:36:23:a8:f3:c1:9e:f2:12:02:6f:
        db:3c:38:b5:0b:e4:0b:ea:f9:17:81:b2:6e:2c:34:7c:35:dc:
        9f:e8:b9:0d

If PKI-based authentication is being used and HP FlexFabric Switch does not validate certificates by constructing a certification path to an accepted trust anchor, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to validate certificates by constructing a certification path to an accepted trust anchor when utilizing PKI-based authentication.

Configure PKI entity:
[HP] pki entity HP
[HP-pki-entity-HP] common-name HP
[HP-pki-entity-HP] country US
[HP-pki-entity-HP] locality Littleton
[HP-pki-entity-HP] organization-unit STG
[HP-pki-entity-HP] organization HP
[HP-pki-entity-HP] state MA
[HP-pki-entity-HP] ip 15.252.76.101
[HP-pki-entity-HP] quit

Configure PKI domain:
[HP] pki domain HP
[HP-pki-domain-HP] certificate request entity HP
[HP-pki-domain-HP] public-key rsa general name hostkey
[HP-pki-domain-HP] source ip 15.252.76.101
[HP-pki-domain-HP] undo crl check enable
[HP-pki-domain-HP] quit

Submit certificate request on the switch:
[HP] pki request-certificate domain HP pkcs10

Transfer and import downloaded CA and user certificates to the switch:
[HP] pki import domain jitc pem ca filename rae-root-ca.cer
[HP] pki import domain jitc pem local filename HP.cer

Configure a local user:
[HP] local-user pkiuser
[HP-luser-pkiuser] service-type ssh
[HP-luser-pkiuser] authorization-attribute user-role network-admin
[HP-luser-pkiuser] password

Set this user as an SSH user and set authentication type to password-public key and assign pki domain:
[HP] ssh user pkiuser service-type all authentication-type password-publickey assign pki-domain hp

Note: Configuration required on the server side is not covered here.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66865r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66219'
  tag rid: 'SV-80709r1_rule'
  tag stig_id: 'HFFS-ND-000064'
  tag gtitle: 'SRG-APP-000175-NDM-000262'
  tag fix_id: 'F-72295r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
