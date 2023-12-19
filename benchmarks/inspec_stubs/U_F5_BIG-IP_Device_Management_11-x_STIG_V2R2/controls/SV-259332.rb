control 'SV-259332' do
  title 'The BIG-IP appliance must be configured to restrict a consistent inbound IP for the entire management session.'
  desc 'This setting helps to limit the effects of denial-of-service attacks by employing antisession hijacking security safeguards. Session hijacking, also called cookie hijacking, is the exploitation of a valid computer session to gain unauthorized access to an application. The attacker steals (or hijacks) the cookies from a valid user and attempts to use them for authentication.'
  desc 'check', 'Navigate to the BIG-IP System manager >> System >> Preferences.

Review the "Security Settings" section.

Verify "Restrict A Consistent Inbound IP For The Entire Session" is enabled.

If the BIG-IP appliance is not configured to restrict a consistent inbound IP for the entire session for management sessions, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to restrict a consistent inbound IP for the entire session for management sessions.

Set "Restrict A Consistent Inbound IP For The Entire Session" to enabled.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-63070r939151_chk'
  tag severity: 'medium'
  tag gid: 'V-259332'
  tag rid: 'SV-259332r939163_rule'
  tag stig_id: 'F5BI-DM-000163'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-62979r939152_fix'
  tag 'documentable'
  tag legacy: ['SV-74615', 'V-60185']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
