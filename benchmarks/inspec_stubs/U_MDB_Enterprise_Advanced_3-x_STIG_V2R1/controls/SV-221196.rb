control 'SV-221196' do
  title 'MongoDB must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.'
  desc 'DBMSs handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to MongoDB or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.

'
  desc 'check', 'Review the documentation and/or specification for the organization-defined information. 

If any data is PII, classified or is deemed by the organization to be encrypted at rest, this is a finding.

Verify the mongod command line contain the following options:

--enableEncryption 
--kmipServerName <KMIP Server HostName>
--kmipPort <KMIP server port>
--kmipServerCAFile ca.pem 
--kmipClientCertificateFile client.pem

If these above options are not part of the mongod command line, this is a finding.

Items in the <> above and starting with kmip* are specific to the KMIP appliance and need to be set according to the KMIP appliance configuration.'
  desc 'fix', 'Configure MongoDB to use the Encrypted Storage Engine and a KMIP appliance as documented here:

https://docs.mongodb.com/v3.4/core/security-encryption-at-rest/
https://docs.mongodb.com/v3.4/tutorial/configure-encryption/'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 3.x'
  tag check_id: 'C-22911r411082_chk'
  tag severity: 'medium'
  tag gid: 'V-221196'
  tag rid: 'SV-221196r411084_rule'
  tag stig_id: 'MD3X-00-000740'
  tag gtitle: 'SRG-APP-000428-DB-000386'
  tag fix_id: 'F-22900r411083_fix'
  tag satisfies: ['SRG-APP-000428-DB-000386', 'SRG-APP-000429-DB-000387']
  tag 'documentable'
  tag legacy: ['SV-96633', 'V-81919']
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
