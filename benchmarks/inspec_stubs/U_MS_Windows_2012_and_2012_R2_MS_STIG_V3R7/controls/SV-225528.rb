control 'SV-225528' do
  title 'The Fax service must be disabled if installed.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.'
  desc 'check', 'Verify the Fax (fax) service is not installed or is disabled.

Run "Services.msc".

If the following is installed and not disabled, this is a finding:

Fax (fax)'
  desc 'fix', 'Remove or disable the Fax (fax) service.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27227r471926_chk'
  tag severity: 'medium'
  tag gid: 'V-225528'
  tag rid: 'SV-225528r569185_rule'
  tag stig_id: 'WN12-SV-000100'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27215r471927_fix'
  tag 'documentable'
  tag legacy: ['V-26600', 'SV-52236']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
