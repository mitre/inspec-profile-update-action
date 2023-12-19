control 'SV-213912' do
  title 'The Database Master Key must be encrypted by the Service Master Key, where a Database Master Key is required and another encryption method has not been specified.'
  desc 'When not encrypted by the Service Master Key, system administrators or application administrators may access and use the Database Master Key to view sensitive data that they are not authorized to view. Where alternate encryption means are not feasible, encryption by the Service Master Key may be necessary. To help protect sensitive data from unauthorized access by DBAs, mitigations may be in order. Mitigations may include automatic alerts or other audit events when the Database Master Key is accessed outside of the application or by a DBA account.'
  desc 'check', 'If no databases require encryption, this is not a finding. 

From the query prompt: 

SELECT name 
FROM [master].sys.databases 
WHERE is_master_key_encrypted_by_server = 1 
AND owner_sid <> 1 
AND state = 0; 
(Note that this query assumes that the [sa] account is not used as the owner of application databases, in keeping with other STIG guidance. If this is not the case, modify the query accordingly.) 

If no databases are returned by the query, this is not a finding. 

For any databases returned, verify in the System Security Plan that encryption of the Database Master Key using the Service Master Key is acceptable and approved by the Information Owner, and the encrypted data does not require additional protections to deter or detect DBA access. If not approved, this is a finding. 

If approved and additional protections are required, then verify the additional requirements are in place in accordance with the System Security Plan. These may include additional auditing on access of the Database Master Key with alerts or other automated monitoring. 

If the additional requirements are not in place, this is a finding.'
  desc 'fix', 'Where possible, encrypt the Database Master Key with a password known only to the application administrator.

Where not possible, configure additional audit events or alerts to detect unauthorized access to the Database Master Key by users not authorized to view sensitive data.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15130r313168_chk'
  tag severity: 'medium'
  tag gid: 'V-213912'
  tag rid: 'SV-213912r879642_rule'
  tag stig_id: 'SQL6-D0-001700'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-15128r313169_fix'
  tag 'documentable'
  tag legacy: ['SV-93793', 'V-79087']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
