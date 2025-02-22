control 'SV-48039' do
  title 'Security configuration tools or equivalent processes must be used to configure and maintain platforms for security compliance.'
  desc 'Security configuration tools such as Group Policies and Security Templates allow system administrators to consolidate security-related system settings into a single configuration file.  These settings can then be applied consistently to any number of Windows machines.'
  desc 'check', 'Verify security configuration tools, or an equivalent process, are being used to configure Windows systems to meet security requirements.  Security configuration tools that are integrated into Windows, such as Group Policies and Security Templates, may be used to configure platforms for security compliance.

If an alternate method is used to configure a system (e.g., manually using the DISA Windows Security STIGs, etc.) that achieves the same configured result, this is acceptable.'
  desc 'fix', 'Implement a process using security configuration tools or the equivalent to configure Windows systems to meet security requirements.'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44778r1_chk'
  tag severity: 'low'
  tag gid: 'V-1128'
  tag rid: 'SV-48039r1_rule'
  tag stig_id: 'WN08-00-000004'
  tag gtitle: 'Security Configuration Tools'
  tag fix_id: 'F-41177r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
