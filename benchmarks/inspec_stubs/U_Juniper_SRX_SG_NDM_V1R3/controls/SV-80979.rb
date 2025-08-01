control 'SV-80979' do
  title 'The Juniper SRX Services Gateway must be configured to use an authentication server to centrally manage authentication and logon settings for remote and nonlocal access.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is a particularly important protection against the insider threat. Audit records for administrator accounts access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device. 

The Juniper SRX supports three methods of user authentication: local password authentication, Remote Authentication Dial-In User Service (RADIUS), and Terminal Access Controller Access Control System Plus (TACACS+). RADIUS and TACACS+ are remote access methods used for management of the Juniper SRX. The local password method will be configured for use only for the account of last resort.

To completely set up AAA authentication, create a user template account (the default name is remote) and specify a system authentication server and an authentication order. See CCI-000213 for more details. The remote user template is not a logon account. Once the AAA server option is configured, any remote or nonlocal access attempts are redirected to the AAA server. Since individual user accounts are not defined on the SRX, the authentication server must be used to manage individual account settings."
  desc 'check', 'Verify the Juniper SRX is configured to support the use of AAA services to centrally manage user authentication and logon settings. 

From the CLI operational mode enter: 
show system radius-server 
or 
show system tacplus-server

If the Juniper SRX has not been configured to support the use RADIUS and/or TACACS+ servers to centrally manage authentication and logon settings for remote and nonlocal access, this is a finding.'
  desc 'fix', 'Configure the Juniper SRX to support the use of AAA services to centrally manage user authentication and logon settings. To completely set up AAA authentication, use a user template account (the default name is remote) and specify a system authentication server and an authentication order. 

[edit]
set system tacplus-server address <server ipaddress> port 1812 secret <shared secret> 

or 

[edit]
set system radius-server address <server ipaddress> port 1812 secret <shared secret> 

Note: DoD policy is that redundant AAA servers are required to mitigate the risk of a failure of the primary AAA device. Also see CCI-000213 for  further details.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67135r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66489'
  tag rid: 'SV-80979r1_rule'
  tag stig_id: 'JUSX-DM-000095'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-72565r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
