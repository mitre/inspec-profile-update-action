control 'SV-252180' do
  title 'MongoDB must maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

This requirement applies only to those applications that are either distributed or can allow access to data nonlocally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.

When receiving data, MongoDB, associated applications, and infrastructure must leverage protection mechanisms.'
  desc 'check', 'If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.

If such information is present, inspect the MongoDB configuration file (default location: /etc/mongod.conf) for the following entries:

net:
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/mongodb.pem
    CAFile: /etc/ssl/caToValidateClientCertificates.pem
    allowInvalidCertificates: false
    allowConnectionsWithoutCertificates: false
    FIPSMode: true

If net.tls.mode is not set to requireTLS, this is a finding.'
  desc 'fix', 'Obtain a certificate from a valid DoD certificate authority to be used for encrypted data transmission. 

Modify the %MongoDB configuration file% with TLS configuration options such as:

net:
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/mongodb.pem
    CAFile: /etc/ssl/caToValidateClientCertificates.pem
    allowInvalidCertificates: false
    allowConnectionsWithoutCertificates: false
    FIPSMode: true

Ensue net.tls.mode is set to requireTLS.

Start/stop (restart) all mongod or mongos instances using the %MongoDB configuration file% (default location: /etc/mongod.conf).'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55636r813920_chk'
  tag severity: 'medium'
  tag gid: 'V-252180'
  tag rid: 'SV-252180r855521_rule'
  tag stig_id: 'MD4X-00-006100'
  tag gtitle: 'SRG-APP-000442-DB-000379'
  tag fix_id: 'F-55586r813921_fix'
  tag 'documentable'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
