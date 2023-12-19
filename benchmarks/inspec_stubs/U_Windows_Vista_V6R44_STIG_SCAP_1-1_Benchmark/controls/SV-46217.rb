control 'SV-46217' do
  title 'The Windows Installer Always install with elevated privileges must be disabled.'
  desc 'Standard user accounts must not be granted elevated privileges.  Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Always install with elevated privileges" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-34974'
  tag rid: 'SV-46217r1_rule'
  tag stig_id: 'WINCC-000001'
  tag gtitle: 'Always Install with Elevated Privileges Disabled'
  tag fix_id: 'F-39543r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
