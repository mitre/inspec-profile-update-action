control 'SV-29752' do
  title 'Audit data must be retained for at least one year.'
  desc 'Audit records are essential for investigating system activity after the fact. Retention periods for audit data are determined based on the sensitivity of the data handled by the system.'
  desc 'check', 'Determine whether audit data is retained for at least one year. If the audit data is not retained for at least one year, this is a finding.'
  desc 'fix', 'Ensure the audit data is retained for at least one year.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-66303r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14226'
  tag rid: 'SV-29752r2_rule'
  tag gtitle: 'Archiving Audit Logs'
  tag fix_id: 'F-71691r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
