control 'SV-225531' do
  title 'The Simple TCP/IP Services service must be disabled if installed.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.'
  desc 'check', 'Verify the Simple TCP/IP (simptcp) service is not installed or is disabled. 

Run "Services.msc".

If the following is installed and not disabled, this is a finding:

Simple TCP/IP Services (simptcp)'
  desc 'fix', 'Remove or disable the Simple TCP/IP Services (simptcp) service.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27230r471935_chk'
  tag severity: 'medium'
  tag gid: 'V-225531'
  tag rid: 'SV-225531r569185_rule'
  tag stig_id: 'WN12-SV-000104'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27218r471936_fix'
  tag 'documentable'
  tag legacy: ['V-26605', 'SV-52239']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
