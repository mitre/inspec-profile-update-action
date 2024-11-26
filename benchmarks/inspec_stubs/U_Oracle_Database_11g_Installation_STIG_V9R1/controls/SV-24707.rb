control 'SV-24707' do
  title 'Database data encryption controls should be configured in accordance with application requirements.'
  desc 'Access to sensitive data may not always be sufficiently protected by authorizations and require encryption. In some cases, the required encryption may be provided by the application accessing the database. In others, the DBMS may be configured to provide the data encryption. When the DBMS provides the encryption, the requirement must be implemented as identified by the Information Owner to prevent unauthorized disclosure or access.'
  desc 'check', 'Review the System Security Plan and note sensitive data identified by the Information Owner as requiring encryption using DBMS features administered by the DBA.

If no sensitive data is present or encryption of sensitive data is not required by the Information Owner, this check is Not a Finding.

Review the encryption configuration against the System Security Plan specification.

If the specified encryption is not configured, this is a Finding.'
  desc 'fix', 'Configure DBMS encryption features and functions as required by the System Security Plan.

Discrepancies between what features are and are not available should be resolved with the Information Owner, Application Developer and DBA as overseen by the IAO.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29314r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15143'
  tag rid: 'SV-24707r1_rule'
  tag stig_id: 'DG0106-ORACLE11'
  tag gtitle: 'Database data encryption configuration'
  tag fix_id: 'F-26346r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
