control 'SV-55935' do
  title 'Domain accounts used to manage a SQL Server platform must be different from those used to manage other platforms.'
  desc 'Separate accounts used to manage the SQL Server platform help prevent a lateral move within an environment if SQL were to be compromised.'
  desc 'check', 'Determine the accounts being used to manage the SQL Server operating system.  Determine whether the same accounts are being used to manage other platforms. If the same account is used to manage more than one platform, this is a finding.
Note: If, because of the application configuration, there are multiple instances of SQL that would share a given exploit, a single account would be allowed to be used for the group and would not be considered a finding.'
  desc 'fix', 'Set up and use separate domain accounts to manage the SQL Server platform.  These accounts must be different from those used to manage other platforms.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-49206r1_chk'
  tag severity: 'medium'
  tag gid: 'V-43196'
  tag rid: 'SV-55935r2_rule'
  tag stig_id: 'SQL2-00-024600'
  tag gtitle: 'SRG-APP-999999-DB-000209'
  tag fix_id: 'F-48769r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
