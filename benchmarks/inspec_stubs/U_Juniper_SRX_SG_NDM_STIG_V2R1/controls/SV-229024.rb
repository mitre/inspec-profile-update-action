control 'SV-229024' do
  title 'The Juniper SRX Services Gateway must be configured to use an authentication server to centrally apply authentication and logon settings for remote and nonlocal access for device management.'
  desc "Centralized application (e.g., TACACS+, RADIUS) of authentication settings increases the security of remote and nonlocal access methods. This control is a particularly important protection against the insider threat. Audit records for administrator accounts access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device.

This requirement references identification and authentication and does not prevent the configuration of privileges using the remote template account (CCI-000213)."
  desc 'check', 'Verify the Juniper SRX is configured to support the use of AAA services to centrally apply user authentication and logon settings. 

From the CLI operational mode enter: 
show system radius-server 
or 
show system tacplus-server

If the Juniper SRX has not been configured to support the use of RADIUS and/or TACACS+ servers to centrally apply authentication and logon settings for remote and nonlocal access, this is a finding.'
  desc 'fix', 'Configure the Juniper SRX to support the use of AAA services to centrally apply user authentication and logon settings. 

[edit]
set system tacplus-server address <server ipaddress> port 1812 secret <shared secret> 

or 

[edit]
set system radius-server address <server ipaddress> port 1812 secret <shared secret>'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-31339r518248_chk'
  tag severity: 'medium'
  tag gid: 'V-229024'
  tag rid: 'SV-229024r518250_rule'
  tag stig_id: 'JUSX-DM-000096'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31316r518249_fix'
  tag 'documentable'
  tag legacy: ['SV-80981', 'V-66491']
  tag cci: ['CCI-000366', 'CCI-002361']
  tag nist: ['CM-6 b', 'AC-12']
end
