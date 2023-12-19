control 'SV-226122' do
  title 'Audit data must be retained for at least one year.'
  desc 'Audit records are essential for investigating system activity after the fact.  Retention periods for audit data are determined based on the sensitivity of the data handled by the system.'
  desc 'check', 'Determine whether audit data is retained for at least one year.  If the audit data is not retained for at least a year, this is a finding.'
  desc 'fix', 'Ensure the audit data is retained for at least a year.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27824r475689_chk'
  tag severity: 'medium'
  tag gid: 'V-226122'
  tag rid: 'SV-226122r794317_rule'
  tag stig_id: 'WN12-AU-000201'
  tag gtitle: 'SRG-OS-000255-GPOS-00096'
  tag fix_id: 'F-27812r475690_fix'
  tag 'documentable'
  tag legacy: ['SV-51563', 'V-36671']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
