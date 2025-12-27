control 'SV-252139' do
  title 'If passwords are used for authentication, MongoDB must transmit only encrypted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

DBMS passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database.

'
  desc 'check', 'In the MongoDB database configuration file (default location: /etc/mongod.conf), verify the following parameters in the net.tls: (network TLS) section of the file:

net:
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/mongodb.pem
    CAFile: /etc/ssl/caToValidateClientCertificates.pem
    allowInvalidCertificates: false
    allowConnectionsWithoutCertificates: false

If the net.tls: parameter is not present, this is a finding.

If the net.tls.certificateKeyFile parameter is not present, this is a finding.

If the net.tls.CAFile parameter is not present, this is a finding.

If the net.tls.allowInvalidCertificates parameter is found and set to true, this is a finding.

If the net.tls.allowConnectionsWithoutCertificates parameter is found and set to true, this is a finding.'
  desc 'fix', 'In the MongoDB database configuration file (default location: /etc/mongod.conf), ensure the following parameters are present in the net.tls (network TLS) section of the file and are configured correctly for the site and server:

net:
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/mongodb.pem
    CAFile: /etc/ssl/caToValidateClientCertificates.pem
    allowInvalidCertificates: false
    allowConnectionsWithoutCertificates: false

Stop/start (restart) the mongod or mongos instance using this configuration.

More information for configuring TLS/SSL for MongoDB can be found here:
https://docs.mongodb.com/v4.4/tutorial/configure-ssl/'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55595r813797_chk'
  tag severity: 'medium'
  tag gid: 'V-252139'
  tag rid: 'SV-252139r813799_rule'
  tag stig_id: 'MD4X-00-000600'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag fix_id: 'F-55545r816979_fix'
  tag satisfies: ['SRG-APP-000172-DB-000075', 'SRG-APP-000175-DB-000067']
  tag 'documentable'
  tag cci: ['CCI-000197', 'CCI-000185']
  tag nist: ['IA-5 (1) (c)', 'IA-5 (2) (b) (1)']
end
