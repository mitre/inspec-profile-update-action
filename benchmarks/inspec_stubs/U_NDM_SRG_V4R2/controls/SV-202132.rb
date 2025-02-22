control 'SV-202132' do
  title 'The network device must be configured to use an authentication server for the purpose of authenticating users prior to granting administrative access.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Review the network device configuration to verify that the device is configured to use an authentication server as primary source for authentication.

If the network device is not configured to use an authentication server for the purpose of authenticating users prior to granting administrative access, this is a finding.'
  desc 'fix', 'Step 1: Configure the network device to use an authentication server.

Step 2: Configure the authentication order to use the authentication server as primary source for authentication.

Step 3: Configure all network connections associated with a device management to use an authentication server for the purpose of login authentication.'
  impact 0.7
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2258r382070_chk'
  tag severity: 'high'
  tag gid: 'V-202132'
  tag rid: 'SV-202132r879887_rule'
  tag stig_id: 'SRG-APP-000516-NDM-000336'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-2259r539623_fix'
  tag 'documentable'
  tag legacy: ['SV-69545', 'V-55299']
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
