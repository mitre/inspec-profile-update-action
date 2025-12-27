control 'SV-53945' do
  title 'Database Master Key passwords must not be stored in credentials within the database.'
  desc 'Storage of the Database Master Key password in a database credential allows decryption of sensitive data by privileged users who may not have a need-to-know requirement to access the
data.'
  desc 'check', 'From the query prompt:
SELECT COUNT(credential_id)
FROM [master].sys.master_key_passwords

If count is not 0, this is a finding.'
  desc 'fix', "Use the stored procedure sp_control_dbmasterkey_password to remove any credentials that
store Database Master Key passwords.
From the query prompt:
EXEC SP_CONTROL_DBMASTERKEY_PASSWORD @db_name = '[database name]', @action
= N'drop'"
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47952r1_chk'
  tag severity: 'medium'
  tag gid: 'V-41416'
  tag rid: 'SV-53945r2_rule'
  tag stig_id: 'SQL2-00-024200'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-46845r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
