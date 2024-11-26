control 'SV-220387' do
  title 'MarkLogic Server must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.'
  desc 'DBMSs handling data requiring data-at-rest protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to the DBMS or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). 

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.'
  desc 'check', 'Review the system documentation to determine whether the organization has defined the information at rest that is to be protected from modification, which must include, at a minimum, PII and classified information.

If no information is identified as requiring such protection, this is not a finding.

Review system settings to determine if any of the information defined as requiring cryptographic protection from modification, is not encrypted in a manner that provides the required level of protection.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Databases icon.
2. Click the database that is to be checked.
3. If the "data encryption" drop-down is set to ON, this is not a finding, and no further checks need to be performed.
4. If the "data encryption" drop-down is set to OFF, continue the check.
5. If the "data encryption" drop-down is set to default-cluster, continue the check with the steps below:
a. Click on the Clusters icon.
b. Click [Cluster Name].
c. Click the Keystore Tab.
d. If the Cluster Default Encryption configuration is OFF, this is a finding.

Findings Matrix
-------------------------------------------------------
Database Cfg. | Cluster Cfg | Finding
--------------------------------------------------------
ON | *Any* | No
*Any* | Force | No
Default-cluster | Default-on | No
Default-cluster | Default-off | Yes
Off | Default-on | Yes
Off | Default-off | Yes'
  desc 'fix', 'Configure MarkLogic to provide the required level of cryptographic protection.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Databases icon.
2. Click the database that is to be fixed.
3. Select ON from the data encryption drop-down.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22102r401612_chk'
  tag severity: 'medium'
  tag gid: 'V-220387'
  tag rid: 'SV-220387r855492_rule'
  tag stig_id: 'ML09-00-008500'
  tag gtitle: 'SRG-APP-000428-DB-000386'
  tag fix_id: 'F-22091r401613_fix'
  tag 'documentable'
  tag legacy: ['SV-110123', 'V-101019']
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
