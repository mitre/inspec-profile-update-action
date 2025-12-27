control 'SV-77349' do
  title 'Riverbed Optimization System (RiOS) must enforce the limit of three (3) consecutive invalid logon attempts by a user during a 15-minute time period for device console access.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Verify that RiOS is configured to limit the number of invalid logon attempts during a 15 minute period to 3.

Login to the device console to access the command line interface (CLI)

Type: show authentication policy

Verify that "Maximum unsuccessful logins before account lockout:" is set to "3"
Verify that "Wait before account unlock:" is set to "900" seconds

If "Maximum unsuccessful logins before account lockout" is not set to "3" and/or "Wait before account unlock" is not set to "900" seconds, this is a finding.'
  desc 'fix', 'Configure RiOS to limit the number of invalid logon attempts to 3 during a 15 minute period.

Login to the device console to access the command line interface (CLI)

Type: enable
Type: conf t
Type: authentication policy template strong
Scroll down to "Maximum unsuccessful logins before account lockout:" and type "3"
Under "Wait before account unlock:" and type "900" Seconds
Type: write memory'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63653r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62859'
  tag rid: 'SV-77349r1_rule'
  tag stig_id: 'RICX-DM-000024'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-68777r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
