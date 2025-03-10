control 'SV-221197' do
  title 'MongoDB must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.

When transmitting data, MongoDB, associated applications, and infrastructure must leverage transmission protection mechanisms.'
  desc 'check', 'Review the system information/specification for information indicating a strict requirement for data integrity and confidentiality when data is being prepared to be transmitted. 

If such information is absent therein, this is not a finding. 

If such information is present, inspect the MongoDB configuration file (default location: /etc/mongod.conf) for the following entries:

net:
ssl:
mode: requireSSL
PEMKeyFile: /etc/ssl/mongodb.pem

If net.ssl.mode is not set to "requireSSL", this is a finding.'
  desc 'fix', 'Stop the MongoDB instance if it is running. Obtain a certificate from a valid DoD certificate authority to be used for encrypted data transmission. Modify the MongoDB configuration file with ssl configuration options such as:

net:
ssl:
mode: requireSSL
PEMKeyFile: /etc/ssl/mongodb.pem

Set "net.ssl.mode" to the "requireSSL".
Set "net.ssl.KeyFile" to the full path of the certificate (.pem) file.

Start/stop (restart) all mongod or mongos instances using the MongoDB configuration file (default location: /etc/mongod.conf).'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 3.x'
  tag check_id: 'C-22912r411085_chk'
  tag severity: 'medium'
  tag gid: 'V-221197'
  tag rid: 'SV-221197r411087_rule'
  tag stig_id: 'MD3X-00-000760'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-22901r411086_fix'
  tag 'documentable'
  tag legacy: ['SV-96635', 'V-81921']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
