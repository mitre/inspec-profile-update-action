control 'SV-25002' do
  title 'Security configuration tools are not being used to configure platforms for security compliance.'
  desc 'Security configuration tools (such as Security Templates and Group Policy) allow system administrators to consolidate all security related system settings into a single configuration file.  These settings can then be applied consistently to any number of Windows machines.'
  desc 'check', 'Verify that security configuration tools, or an equivalent process, is being used to configure Windows systems to meet security requirements.  Security configuration tools that are integrated into Windows (such as Security Templates and Group Policy) should be used to configure platforms for security compliance.

If an alternate method is used to configure a system (e.g., manually using the DISA Windows Security STIGs, etc.) that achieves the same configured result, then this is acceptable.'
  desc 'fix', 'Security configuration tools or equivalent should be used to configure Windows systems to meet security requirements.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-39088r1_chk'
  tag severity: 'low'
  tag gid: 'V-1128'
  tag rid: 'SV-25002r1_rule'
  tag gtitle: 'Security Configuration Tools'
  tag fix_id: 'F-37r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
