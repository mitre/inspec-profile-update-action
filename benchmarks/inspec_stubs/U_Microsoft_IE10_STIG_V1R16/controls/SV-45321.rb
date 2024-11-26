control 'SV-45321' do
  title 'Suggested Sites functionality must be disallowed.'
  desc "This policy setting controls the Suggested Sites feature, which recommends sites based on the user's browsing activity. Suggested Sites reports a user's browsing history to Microsoft to store and monitor user page activity to suggest sites the user might want to visit. If you enable this policy setting, the user will not be prompted to enable the Suggested Sites and the user's browsing activities will be sent and stored online to produce suggestions. If you disable this policy setting, the entry points and functionality associated with this feature will be disabled."
  desc 'check', 'The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> "Turn on Suggested Sites" must be "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Suggested Sites

Criteria: If the value "Enabled is REG_DWORD = 0", this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> "Turn on Suggested Sites" to "Disabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42669r2_chk'
  tag severity: 'medium'
  tag gid: 'V-30776'
  tag rid: 'SV-45321r2_rule'
  tag stig_id: 'DTBI765'
  tag gtitle: 'DTBI765 - Suggested Sites Functionality'
  tag fix_id: 'F-38717r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
