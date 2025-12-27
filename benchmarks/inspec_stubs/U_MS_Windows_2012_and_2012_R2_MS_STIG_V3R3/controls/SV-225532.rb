control 'SV-225532' do
  title 'The Telnet service must be disabled if installed.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.'
  desc 'check', 'Verify the Telnet (tlntsvr) service is not installed or is disabled. 

Run "Services.msc".

If the following is installed and not disabled, this is a finding:

Telnet (tlntsvr)'
  desc 'fix', 'Remove or disable the Telnet (tlntsvr) service.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27231r471938_chk'
  tag severity: 'medium'
  tag gid: 'V-225532'
  tag rid: 'SV-225532r569185_rule'
  tag stig_id: 'WN12-SV-000105'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-27219r471939_fix'
  tag 'documentable'
  tag legacy: ['V-26606', 'SV-52240']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
