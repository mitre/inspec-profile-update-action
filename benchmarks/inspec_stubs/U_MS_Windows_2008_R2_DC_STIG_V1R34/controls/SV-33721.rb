control 'SV-33721' do
  title 'The Telnet service will be disabled.'
  desc 'Unnecessary Services increase the attack surface of a system.  Some of these services may not support required levels of authentication or encryption.'
  desc 'check', 'Verify the service is not installed or is disabled.  

Select “Start”.
Select “Run”.
Enter "Services.msc" in the run box.
Respond to any User Account Control prompts.

If the following is installed and not disabled, this is a finding:

Telnet (tlntsvr)'
  desc 'fix', 'Remove or disable the Telnet (tlntsvr) service.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-34146r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26606'
  tag rid: 'SV-33721r1_rule'
  tag stig_id: 'WINSV-000105'
  tag gtitle: 'Telnet Service Disabled'
  tag fix_id: 'F-29836r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
