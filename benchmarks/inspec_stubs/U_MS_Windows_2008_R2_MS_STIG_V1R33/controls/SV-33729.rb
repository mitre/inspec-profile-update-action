control 'SV-33729' do
  title 'The Peer Networking Identity Manager service will be disabled.'
  desc 'Unnecessary Services increase the attack surface of a system.  Some of these services may not support required levels of authentication or encryption.'
  desc 'check', 'Verify the service is not installed or is disabled.  

Select “Start”.
Select “Run”.
Enter "Services.msc" in the run box.
Respond to any User Account Control prompts.

If the following is installed and not disabled, this is a finding:

Peer Networking Identity Manager (p2pimsvc)'
  desc 'fix', 'Remove or disable the Peer Networking Identity Manager (p2pimsvc) service.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-34150r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26604'
  tag rid: 'SV-33729r1_rule'
  tag stig_id: 'WINSV-000103'
  tag gtitle: 'Peer Networking Identity Manager Service Disabled'
  tag fix_id: 'F-29840r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
