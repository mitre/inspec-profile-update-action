control 'SV-226355' do
  title 'The Peer Networking Identity Manager service must be disabled if installed.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.'
  desc 'check', 'Verify the Peer Network Identity Manager (p2pimsvc) service is not installed or is disabled. 

Run "Services.msc".

If the following is installed and not disabled, this is a finding:

Peer Networking Identity Manager (p2pimsvc)'
  desc 'fix', 'Remove or disable the Peer Networking Identity Manager (p2pimsvc) service.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28057r476909_chk'
  tag severity: 'medium'
  tag gid: 'V-226355'
  tag rid: 'SV-226355r569184_rule'
  tag stig_id: 'WN12-SV-000103'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-28045r476910_fix'
  tag 'documentable'
  tag legacy: ['V-26604', 'SV-52238']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
