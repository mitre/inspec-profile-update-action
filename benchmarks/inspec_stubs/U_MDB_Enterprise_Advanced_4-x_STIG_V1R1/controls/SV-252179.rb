control 'SV-252179' do
  title 'MongoDB must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.

When transmitting data, MongoDB, associated applications, and infrastructure must leverage transmission protection mechanisms.'
  desc 'check', 'Review the system information/specification for information indicating a strict requirement for data integrity and confidentiality when data is being prepared to be transmitted. 

If such information is absent therein, this is not a finding. 

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
  desc 'fix', 'Stop the MongoDB instance if it is running.

Obtain a certificate from a valid DoD certificate authority to be used for encrypted data transmission.

Modify the %MongoDB configuration file% with TLS configuration options such as:

net:
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/mongodb.pem
    CAFile: /etc/ssl/caToValidateClientCertificates.pem
    allowInvalidCertificates: false
    allowConnectionsWithoutCertificates: false
    FIPSMode: true

Set net.tls.mode to the requireTLS.
Set net.tls.certificateKeyFile to the full path of the certificate (.pem) file.

Start/stop (restart) all mongod or mongos instances using the %MongoDB configuration file% (default location: /etc/mongod.conf).'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55635r813917_chk'
  tag severity: 'medium'
  tag gid: 'V-252179'
  tag rid: 'SV-252179r813919_rule'
  tag stig_id: 'MD4X-00-006000'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-55585r813918_fix'
  tag 'documentable'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
