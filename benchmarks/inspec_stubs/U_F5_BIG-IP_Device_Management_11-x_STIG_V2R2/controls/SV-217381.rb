control 'SV-217381' do
  title 'The BIG-IP appliance must limit the number of concurrent sessions to the Configuration Utility to 10 or an organization-defined number.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Verify the BIG-IP appliance is configured to limit the number of concurrent sessions to 10 or an organization-defined number.

Navigate to the BIG-IP System manager >> System >> Preferences.

Set "System Settings:" to "Advanced".

Verify "Maximum HTTP Connections to Configuration Utility" is set to the organization-defined number of concurrent sessions.

If neither of these configurations is present, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance either to limit the number of concurrent sessions to 10 or an organization-defined number.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18606r290697_chk'
  tag severity: 'medium'
  tag gid: 'V-217381'
  tag rid: 'SV-217381r879511_rule'
  tag stig_id: 'F5BI-DM-000003'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-18604r290698_fix'
  tag 'documentable'
  tag legacy: ['SV-74521', 'V-60091']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
