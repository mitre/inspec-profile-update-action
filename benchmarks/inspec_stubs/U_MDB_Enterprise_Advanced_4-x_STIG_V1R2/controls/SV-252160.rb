control 'SV-252160' do
  title 'MongoDB must enforce authorized access to all PKI private keys stored/utilized by MongoDB.'
  desc "The DoD standard for authentication is DoD-approved PKI certificates. PKI certificate-based authentication is performed by requiring the certificate holder to cryptographically prove possession of the corresponding private key.

If the private key is stolen, an attacker can use the private key(s) to impersonate the certificate holder. In cases where MongoDB-stored private keys are used to authenticate MongoDB to the system's clients, loss of the corresponding private keys would allow an attacker to successfully perform undetected man in the middle attacks against MongoDB system and its clients.

Both the holder of a digital certificate and the issuing authority must take careful measures to protect the corresponding private key. Private keys should always be generated and protected in FIPS 140-2 or 140-3 validated cryptographic modules.

All access to the private key(s) of MongoDB must be restricted to authorized and authenticated users. If unauthorized users have access to one or more of MongoDB's private keys, an attacker could gain access to the key(s) and use them to impersonate the database on the network or otherwise perform unauthorized actions."
  desc 'check', 'In the MongoDB database configuration file (default location: /etc/mongod.conf), review the following parameters:

net:
   tls:
      mode: requireTLS
      certificateKeyFile: /etc/ssl/mongodb.pem
      CAFile: /etc/ssl/caToValidateClientCertificates.pem

Verify ownership, group ownership, and permissions for the MongoDB config file (default: /etc/mongod.conf), the PEMKeyFile (default /etc/ssl/mongodb.pem), and the CAFile (default /etc/ssl/caToValidateClientCertificates.pem).

For each file, run following command and review its output:
ls -al filepath

example output:
-rw------- 1 mongod mongod 566 Apr 26 20:20 filepath

If the user owner is not mongod, this is a finding.

If the group owner is not mongod, this is a finding.

If the file is more permissive than 600, this is a finding.'
  desc 'fix', 'To set proper ownership, group ownership, and permissions, run these commands:
chown mongod:mongod /etc/ssl/mongodb.pem
chmod 600 /etc/ssl/mongodb.pem
chown mongod:mongod /etc/ssl/caToValidateClientCertificates.pem
chmod 600 /etc/ssl/caToValidateClientCertificates.pem'
  impact 0.7
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55616r813860_chk'
  tag severity: 'high'
  tag gid: 'V-252160'
  tag rid: 'SV-252160r863325_rule'
  tag stig_id: 'MD4X-00-003100'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag fix_id: 'F-55566r813861_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
