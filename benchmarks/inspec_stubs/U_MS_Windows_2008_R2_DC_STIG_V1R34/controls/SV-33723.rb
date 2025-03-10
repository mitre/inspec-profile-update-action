control 'SV-33723' do
  title 'The Fax service will be disabled.'
  desc 'Unnecessary Services increase the attack surface of a system.  Some of these services may not support required levels of authentication or encryption.'
  desc 'check', 'Verify the service is not installed or is disabled.

Select “Start”.
Select “Run”.
Enter "Services.msc" in the run box.
Respond to any User Account Control prompts.

If the following is installed and not disabled, this is a finding:

Fax (fax)'
  desc 'fix', 'Remove or disable the Fax (fax) service.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-34147r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26600'
  tag rid: 'SV-33723r1_rule'
  tag stig_id: 'WINSV-000100'
  tag gtitle: 'Fax Service Disabled'
  tag fix_id: 'F-29837r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
