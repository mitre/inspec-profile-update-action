control 'SV-77357' do
  title 'Riverbed Optimization System (RiOS) must limit the number of concurrent sessions to one (1) for each administrator account and/or administrator account type.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.

Recommended best practice for authentication and authorization is to leverage an AAA server (e.g., TACACS or RADIUS). Password of Last Resort is not affected by this requirement. Note that this is a hidden CLI command. Access to the device management console is not affected by this command.'
  desc 'check', 'Verify that RiOS is configured to limit the number of concurrent sessions to one (1) for each administrator account and/or administrator account type. This requirement does not apply to the Admin account.

Navigate to the device CLI
Type: enable
Type: show username <user-other-than-admin> detailed

Verify that "Maximum Logins" is set to "1"

If "Maximum Logins" is not set to "1", this is a finding.'
  desc 'fix', 'Configure the number of concurrent sessions to an organization define number for each administrator account and/or administrator type account.

Navigate to the device CLI
Type: enable
Type: conf t
Type: authentication policy user <user name> max-logins 1
Type: write memory

Settings are now saved to memory.'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63661r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62867'
  tag rid: 'SV-77357r1_rule'
  tag stig_id: 'RICX-DM-000034'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-68785r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
