control 'SV-81899' do
  title 'SQL Server must implement and/or support cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.'
  desc 'Databases holding data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to the DBMS or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). 

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.'
  desc 'check', 'Review the system documentation to determine whether the organization has defined the information at rest that is to be protected from modification, which must include, at a minimum, PII and classified information.

If no information is identified as requiring such protection, this is not a finding.

Review the configuration of SQL Server, Windows, and additional software as relevant.

If full-disk encryption is required, and Windows or the storage system is not configured for this, this is a finding.

If database transparent data encryption (TDE) is called for, check whether it is enabled:
In SQL Server Management Studio, Object Explorer, expand the instance and right-click on the database name; select properties.  Select the Options page, State section, Encryption Enabled parameter.

If the value displayed is False, this is a finding.

If column encryption, done via SQL Server features, is required, review the definitions and contents of the relevant tables and columns.

If any of the information defined as requiring cryptographic protection is not encrypted in a manner that provides the required level of protection, this is a finding.'
  desc 'fix', 'Where full-disk encryption is required, configure Windows and/or the storage system to provide this.

Where transparent data encryption (TDE) is required, deploy the necessary stack of certificates and keys, and set the Encryption Enabled to True.  For guidance from the Microsoft Developer Network on how to do this, perform a web search for "SQL Server 2014 TDE".

Where column encryption is required, deploy the necessary stack of certificates and keys, and enable encryption on the columns in question.  For guidance from the Microsoft Developer Network on how to do this, perform a web search for "SQL Server 2014 Encrypt a Column of Data".'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2014'
  tag check_id: 'C-67987r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67409'
  tag rid: 'SV-81899r1_rule'
  tag stig_id: 'SQL4-00-034700'
  tag gtitle: 'SRG-APP-000428-DB-000386'
  tag fix_id: 'F-73521r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
