control 'SV-91149' do
  title 'Kona Site Defender must reveal error messages only to the ISSO, ISSM, and SCA.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can give configuration details about the network element.

Limiting access to system logs and administrative consoles to authorized personnel will help to mitigate this risk. However, user feedback and error messages should also be restricted by type and content in accordance with security best practices (e.g., ICMP messages)."
  desc 'check', 'Verify that only authorized personnel have access to the Kona Site Defender portal (Luna):

1. Log in to the Akamai Luna Portal (https://control.akamai.com).
2. Select "Configure" and then "Manage Users & Groups".
3. Select the "Roles" tab.
4. Review the personnel list and their current roles.

If non-privileged users can perform privileged functions, this is a finding.'
  desc 'fix', 'Ensure that only authorized personnel have access to the Kona Site Defender portal (Luna):

1. Log in to the Akamai Luna Portal (https://control.akamai.com).
2. Select "Configure" and then "Manage Users & Groups".
3. Select the "Users" tab.
4. Add the correct personnel by clicking the "Create a New User" button or remove existing users by clicking the gear icon next to their entry and selecting "Delete this user".'
  impact 0.7
  ref 'DPMS Target Akamai Edge Security ALG'
  tag check_id: 'C-76113r1_chk'
  tag severity: 'high'
  tag gid: 'V-76453'
  tag rid: 'SV-91149r1_rule'
  tag stig_id: 'AKSD-WF-000039'
  tag gtitle: 'SRG-NET-000402-ALG-000130'
  tag fix_id: 'F-83131r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
