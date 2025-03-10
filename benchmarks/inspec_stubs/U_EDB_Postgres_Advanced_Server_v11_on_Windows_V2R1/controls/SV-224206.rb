control 'SV-224206' do
  title 'The EDB Postgres Advanced Server must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.'
  desc 'DBMSs handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to the DBMS or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.'
  desc 'check', 'If the application owner and Authorizing Official have determined that encryption of data at rest is not required, this is not a finding.

Right-click on <postgresql data directory>, select properties, then select the General tab and the Advanced button.

If the "Encrypt contents to secure data" check box is not checked, this is a finding.'
  desc 'fix', 'Do these steps as the Windows user that is the database administrators (default is enterprisedb), if done as a different user, the Windows database administration user will be unable to view this folder and therefore unable to start the database:

Right-click on <postgresql data directory>, select properties, then select the General tab and the Advanced button. Select option to apply to subfolders and files when prompted.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25879r495636_chk'
  tag severity: 'medium'
  tag gid: 'V-224206'
  tag rid: 'SV-224206r508023_rule'
  tag stig_id: 'EP11-00-009200'
  tag gtitle: 'SRG-APP-000428-DB-000386'
  tag fix_id: 'F-25867r495637_fix'
  tag 'documentable'
  tag legacy: ['SV-109537', 'V-100433']
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
