control 'SV-217390' do
  title 'The BIG-IP appliance must be configured to protect against an individual (or process acting on behalf of an individual) falsely denying having performed system configuration changes.'
  desc 'This requirement supports non-repudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

To meet this requirement, the network device must log administrator access and activity.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that protects against an individual (or process acting on behalf of an individual) falsely denying having performed system configuration changes. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that protects against an individual falsely denying having performed system configuration changes.

If the BIG-IP appliance is not configured to protect against an individual (or process acting on behalf of an individual) falsely denying having performed system configuration changes, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server to protect against an individual (or process acting on behalf of an individual) falsely denying having performed system configuration changes.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18615r290724_chk'
  tag severity: 'medium'
  tag gid: 'V-217390'
  tag rid: 'SV-217390r557520_rule'
  tag stig_id: 'F5BI-DM-000043'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag fix_id: 'F-18613r290725_fix'
  tag 'documentable'
  tag legacy: ['SV-74551', 'V-60121']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
