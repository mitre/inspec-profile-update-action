control 'SV-206605' do
  title 'The DBMS must implement cryptographic mechanisms preventing the unauthorized disclosure of organization-defined information at rest on organization-defined information system components.'
  desc 'DBMSs handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to the DBMS or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). 

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.'
  desc 'check', 'Review the system documentation to determine whether the organization has defined the information at rest that is to be protected from disclosure, which must include, at a minimum, PII and classified information.

If the documentation indicates no information requires such protections, this is not a finding.

Review the configuration of the DBMS, operating system/file system, and additional software as relevant.

If any of the information defined as requiring protection is not encrypted in a manner that provides the required level of protection and is not physically secured to the required level, this is a finding.'
  desc 'fix', 'Configure the DBMS, operating system/file system, and additional software as relevant, to provide the required level of cryptographic protection for information requiring cryptographic protection against disclosure.

Secure the premises, equipment, and media to provide the required level of physical protection.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6865r291483_chk'
  tag severity: 'medium'
  tag gid: 'V-206605'
  tag rid: 'SV-206605r617447_rule'
  tag stig_id: 'SRG-APP-000429-DB-000387'
  tag gtitle: 'SRG-APP-000429'
  tag fix_id: 'F-6865r291484_fix'
  tag 'documentable'
  tag legacy: ['SV-72601', 'V-58171']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
