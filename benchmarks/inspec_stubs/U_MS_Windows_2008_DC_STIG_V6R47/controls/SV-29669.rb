control 'SV-29669' do
  title 'Security configuration tools or equivalent processes must be used to configure and maintain platforms for security compliance.'
  desc 'Security configuration tools such as Group Policies and Security Templates allow system administrators to consolidate security-related system settings into a single configuration file.  These settings can then be applied consistently to any number of Windows systems.'
  desc 'check', 'Verify security configuration tools or equivalent processes are being used to configure Windows systems to meet security requirements.  If security configuration tools or equivalent processes are not used, this is a finding.

Security configuration tools that are integrated into Windows, such as Group Policies and Security Templates, may be used to configure platforms for security compliance.

If an alternate method is used to configure a system (e.g., manually using the DISA Windows Security STIGs, etc.) and the same configured result is achieved, this is acceptable.'
  desc 'fix', 'Implement a process using security configuration tools or the equivalent to configure Windows systems to meet security requirements.'
  impact 0.3
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-51985r1_chk'
  tag severity: 'low'
  tag gid: 'V-1128'
  tag rid: 'SV-29669r2_rule'
  tag gtitle: 'Security Configuration Tools'
  tag fix_id: 'F-53867r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
