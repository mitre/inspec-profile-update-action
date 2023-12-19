control 'SV-24798' do
  title 'Access grants to sensitive data should be restricted to authorized user roles.'
  desc 'Unauthorized access to sensitive data may compromise the confidentiality of personnel privacy, threaten national security or compromise a variety of other sensitive operations. Access controls are best managed by defining requirements based on distinct job functions and assigning access based on the job function assigned to the individual user.'
  desc 'check', 'If no data is identified as being sensitive or classified by the Information Owner, in the System Security Plan or in the AIS Functional Architecture documentation, this check is Not a Finding.

if no identified sensitive or classified data requires encryption by the Information Owner in the System Security Plan and/or AIS Functional Architecture documentation, this check is Not a Finding.

Review data access requirements for sensitive data as identified and assigned by the Information Owner in the System Security Plan.

Review the access controls for sensitive data configured in the database.

If the configured access controls do not match those defined in the System Security Plan, this is a Finding.'
  desc 'fix', 'Define, document and implement all sensitive data access controls based on job function in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29369r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15642'
  tag rid: 'SV-24798r1_rule'
  tag stig_id: 'DG0138-ORACLE11'
  tag gtitle: 'DBMS access to sensitive data'
  tag fix_id: 'F-26394r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
