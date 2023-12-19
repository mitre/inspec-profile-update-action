control 'SV-226353' do
  title 'The Fax service must be disabled if installed.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.'
  desc 'check', 'Verify the Fax (fax) service is not installed or is disabled.

Run "Services.msc".

If the following is installed and not disabled, this is a finding:

Fax (fax)'
  desc 'fix', 'Remove or disable the Fax (fax) service.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28055r476903_chk'
  tag severity: 'medium'
  tag gid: 'V-226353'
  tag rid: 'SV-226353r794633_rule'
  tag stig_id: 'WN12-SV-000100'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-28043r476904_fix'
  tag 'documentable'
  tag legacy: ['SV-52236', 'V-26600']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
