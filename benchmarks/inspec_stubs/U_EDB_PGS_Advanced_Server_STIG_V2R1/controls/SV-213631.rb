control 'SV-213631' do
  title 'The EDB Postgres Advanced Server must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.'
  desc 'DBMSs handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to the DBMS or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). 

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.'
  desc 'check', 'Review the system documentation to determine whether the organization has defined the information at rest that is to be protected from modification, which must include, at a minimum, PII and classified information.

If no information is identified as requiring such protection, this is not a finding.

Review the configuration of the DBMS, operating system/file system, and additional software as relevant.

If any of the information defined as requiring cryptographic protection from modification is not encrypted in a manner that provides the required level of protection, this is a finding.'
  desc 'fix', 'Create an encrypted partition to host the "<postgresql data directory>" directory. This can be done at the OS level with a technology such as db-crypt or other encryption technologies provided by third-party tools.

If only certain columns require encryption, use pgcrypt to encrypt those columns as documented here: 

http://www.postgresql.org/docs/current/static/pgcrypto.html'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14853r290205_chk'
  tag severity: 'medium'
  tag gid: 'V-213631'
  tag rid: 'SV-213631r508024_rule'
  tag stig_id: 'PPS9-00-009200'
  tag gtitle: 'SRG-APP-000428-DB-000386'
  tag fix_id: 'F-14851r290206_fix'
  tag 'documentable'
  tag legacy: ['SV-83619', 'V-69015']
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
