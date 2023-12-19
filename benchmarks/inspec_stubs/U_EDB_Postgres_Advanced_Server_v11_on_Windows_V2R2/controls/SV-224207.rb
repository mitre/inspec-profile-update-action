control 'SV-224207' do
  title 'The EDB Postgres Advanced Server must implement cryptographic mechanisms preventing the unauthorized disclosure of organization-defined information at rest on organization-defined information system components.'
  desc 'DBMSs handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to the DBMS or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

The decision whether and what to encrypt rests with the data owner and is influenced by the physical measures taken to secure the equipment and media on which the information resides.'
  desc 'check', 'If the application owner and Authorizing Official have determined that encryption of data at rest is not required, this is not a finding.

Right-click on <postgresql data directory>, select properties, then select the General tab and the Advanced button.

If the "Encrypt contents to secure data" check box is not checked, this is a finding.'
  desc 'fix', 'Do these steps as the Windows user that is the database administrators (default is enterprisedb). If done as a different user, the Windows database administration user will be unable to view this folder and therefore unable to start the database:

Right-click on <postgresql data directory>, select properties, then select the General tab and the Advanced button. Select option to apply to subfolders and files when prompted.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25880r495638_chk'
  tag severity: 'medium'
  tag gid: 'V-224207'
  tag rid: 'SV-224207r508023_rule'
  tag stig_id: 'EP11-00-009300'
  tag gtitle: 'SRG-APP-000429-DB-000387'
  tag fix_id: 'F-25868r495639_fix'
  tag 'documentable'
  tag legacy: ['SV-109539', 'V-100435']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
