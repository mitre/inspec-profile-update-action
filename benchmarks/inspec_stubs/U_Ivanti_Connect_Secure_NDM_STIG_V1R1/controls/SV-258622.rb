control 'SV-258622' do
  title 'The ICS must be configured to limit the number of concurrent sessions to an organization-defined number for each administrator account and/or administrator account type.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'In the ICS Web UI, navigate to Administrators >> Admins Realms >> Admin Realms.
1. Click the configured admin realm being used for CAC/PKI token admin logins.
2. Click the "Authentication Policy" tab.
3. Click "Limits".

If there is any number other than 1 in "Maximum number of sessions per user", this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to Administrators >> Admins Realms >> Admin Realms.
1. Click the configured admin realm being used for CAC/PKI token admin logins.
2. Click the "Authentication Policy" tab, then click "Limits".
3. In "Maximum number of sessions per user", type the number "1".
4. Click "Save Changes".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62362r930552_chk'
  tag severity: 'medium'
  tag gid: 'V-258622'
  tag rid: 'SV-258622r930554_rule'
  tag stig_id: 'IVCS-NM-000690'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-62271r930553_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
