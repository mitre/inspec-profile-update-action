control 'SV-258585' do
  title 'The ICS must be configured to limit the number of concurrent sessions for user accounts to one.'
  desc "VPN gateway management includes the ability to control the number of users and user sessions that utilize a VPN gateway. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.

The intent of this policy is to ensure the number of concurrent sessions is deliberately set to a number based on the site's mission and not left unlimited."
  desc 'check', 'In the ICS Web UI, navigate to Users >> User Realms >> User Realms.
1. If using the default user realm, click "User". Otherwise, click the configured user realm that will be used for user remote access VPN using DOD CAC authentication.
2. Click the "Authentication Policy" tab, then click "Limits".

If the ICS does not limit the number of concurrent sessions for user accounts to "1", this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to Users >> User Realms >> User Realms.
1. If using the default user realm, click "User". Otherwise, click the configured user realm that will be used for user remote access VPN using DOD CAC authentication.
2. Click the "Authentication Policy" tab, then click "Limits".
3. In "Maximum number of sessions per user", type the number "1".
4. Click "Save Changes".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure VPN'
  tag check_id: 'C-62325r930441_chk'
  tag severity: 'medium'
  tag gid: 'V-258585'
  tag rid: 'SV-258585r930443_rule'
  tag stig_id: 'IVCS-VN-000050'
  tag gtitle: 'SRG-NET-000053-VPN-000170'
  tag fix_id: 'F-62234r930442_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
