control 'SV-226040' do
  title 'Security configuration tools or equivalent processes must be used to configure and maintain platforms for security compliance.'
  desc 'Security configuration tools such as Group Policies and Security Templates allow system administrators to consolidate security-related system settings into a single configuration file.  These settings can then be applied consistently to any number of Windows machines.'
  desc 'check', 'Verify security configuration tools or equivalent processes are being used to configure Windows systems to meet security requirements.  If security configuration tools or equivalent processes are not used, this is a finding.

Security configuration tools that are integrated into Windows, such as Group Policies and Security Templates, may be used to configure platforms for security compliance.

If an alternate method is used to configure a system (e.g., manually using the DISA Windows Security STIGs, etc.) and the same configured result is achieved, this is acceptable.'
  desc 'fix', 'Implement a process using security configuration tools or the equivalent to configure Windows systems to meet security requirements.'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27742r475443_chk'
  tag severity: 'low'
  tag gid: 'V-226040'
  tag rid: 'SV-226040r794377_rule'
  tag stig_id: 'WN12-00-000013'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27730r475444_fix'
  tag 'documentable'
  tag legacy: ['SV-52859', 'V-1128']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
