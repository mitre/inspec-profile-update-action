control 'SV-252147' do
  title 'MongoDB must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.'
  desc 'DBMSs handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to MongoDB or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.

'
  desc 'check', 'Review the system documentation to determine whether the organization has defined the information at rest that is to be protected from modification, which must include, at a minimum, PII and classified information.

If no information is identified as requiring such protection, this is not a finding.

If any data is PII, classified or is deemed by the organization the need to be encrypted at rest, verify the MongoDB configuration file (default location: /etc/mongod.conf) contain the following options:

security:
    enableEncryption: true
 
kmip:
    serverName: %KMIP Server HostName%
    port: %KMIP server port%
    ServerCAFile: %CA PEM file%
    clientCertificateFile: %client PEM file%

If these above options are not part of the MongoDB configuration file, this is a finding.

Items in the above are specific to the KMIP appliance and need to be set according to the KMIP appliance configuration.'
  desc 'fix', 'Configure MongoDB to use the Encrypted Storage Engine and a KMIP appliance as documented here:

https://docs.mongodb.com/v4.4/core/security-encryption-at-rest/
https://docs.mongodb.com/v4.4/tutorial/configure-encryption/'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55603r813821_chk'
  tag severity: 'medium'
  tag gid: 'V-252147'
  tag rid: 'SV-252147r855506_rule'
  tag stig_id: 'MD4X-00-001400'
  tag gtitle: 'SRG-APP-000428-DB-000386'
  tag fix_id: 'F-55553r813822_fix'
  tag satisfies: ['SRG-APP-000428-DB-000386', 'SRG-APP-000429-DB-000387']
  tag 'documentable'
  tag cci: ['CCI-002475', 'CCI-002476']
  tag nist: ['SC-28 (1)', 'SC-28 (1)']
end
