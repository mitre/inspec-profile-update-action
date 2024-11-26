control 'SV-221198' do
  title 'MongoDB must maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

This requirement applies only to those applications that are either distributed or can allow access to data nonlocally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.

When receiving data, MongoDB, associated applications, and infrastructure must leverage protection mechanisms.'
  desc 'check', 'If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.

If such strict requirement for ensure data integrity and confidentially is present, inspect the MongoDB configuration file (default location: /etc/mongod.conf) for the following entries:

net:
ssl:
mode: requireSSL
PEMKeyFile: /etc/ssl/mongodb.pem

If net.ssl.mode is not set to "requireSSL", this is a finding.'
  desc 'fix', 'Obtain a certificate from a valid DoD certificate authority to be used for encrypted data transmission. 

Modify the MongoDB configuration file (default location: /etc/mongod.conf) with the network configuration options.

net:
ssl:
mode: requireSSL
PEMKeyFile: /etc/ssl/mongodb.pem

Set "net.ssl.mode" to the "requireSSL".
Set "net.ssl.KeyFile" to the full path of the certificate (.pem) file.

Start/stop (restart) all mongod or mongos instances using the MongoDB configuration file (default location: /etc/mongod.conf).'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 3.x'
  tag check_id: 'C-22913r411088_chk'
  tag severity: 'medium'
  tag gid: 'V-221198'
  tag rid: 'SV-221198r411090_rule'
  tag stig_id: 'MD3X-00-000770'
  tag gtitle: 'SRG-APP-000442-DB-000379'
  tag fix_id: 'F-22902r411089_fix'
  tag 'documentable'
  tag legacy: ['SV-96637', 'V-81923']
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
