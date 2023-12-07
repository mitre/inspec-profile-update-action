control 'SV-32255' do
  title 'Security configuration tools or equivalent processes will be used to configure platforms for security compliance.'
  desc 'Security configuration tools, such as Security Templates and Group Policy, allow system administrators to consolidate all security-related system settings into a single configuration file.  These settings can then be applied consistently to any number of Windows machines.  The Security Configuration tools can use the same configuration file to check platforms for compliance with security policy.'
  desc 'check', 'Interview the SA to determine if the Security Configuration tools, or equivalent process, is being used to configure Windows systems to meet security requirements. The Microsoft Security Configuration tools (such as Security Templates and Group Policy that are integrated into Windows) should be used to configure platforms for security compliance. 

If an alternate method is used to configure a system (e.g., manually - using the DISA Windows STIGs, etc.) that achieves the same configured result, then this is acceptable.'
  desc 'fix', 'Security configuration tools or equivalent should be used to configure Windows systems to meet security requirements.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32708r1_chk'
  tag severity: 'low'
  tag gid: 'V-1128'
  tag rid: 'SV-32255r1_rule'
  tag gtitle: 'Security Configuration Tools'
  tag fix_id: 'F-37r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
