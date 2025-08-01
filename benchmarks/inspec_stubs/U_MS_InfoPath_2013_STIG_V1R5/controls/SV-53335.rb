control 'SV-53335' do
  title 'Offline Mode capability to cache queries for offline mode must be configured.'
  desc 'InfoPath can function in online mode or offline mode. It can also cache queries for use in offline mode. If offline mode is used and cached queries are enabled, sensitive information contained in the cache could be at risk. By default, InfoPath is in online mode, but offline mode is available to users. Users can also cache queries for use in offline mode.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> InfoPath Options -> Advanced -> Offline "Offline Mode status" is set to "Enabled (Enabled, InfoPath not in Offline Mode)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\InfoPath\\editor\\offline

Criteria: If the value CachedModeStatus is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> InfoPath Options -> Advanced -> Offline "Offline Mode status" to "Enabled (Enabled, InfoPath not in Offline Mode)".'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2013'
  tag check_id: 'C-47613r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17758'
  tag rid: 'SV-53335r2_rule'
  tag stig_id: 'DTOO156'
  tag gtitle: 'DTOO156 - Offline Mode Cache'
  tag fix_id: 'F-46265r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
