control 'SV-234475' do
  title 'The UEM server must be configured to have at least one user in defined administrator roles.'
  desc 'Having several administrative roles for the UEM server supports separation of duties. This allows administrator-level privileges to be granted granularly, such as giving application management privileges to one group and security policy privileges to another group. This helps prevent administrators from intentionally or inadvertently altering other settings and configurations of which they may not understand or approve, which can weaken overall security and increase the risk of compromise.

Defined roles:
- Server primary administrator: Responsible for server installation, initial configuration, and maintenance functions. Responsible for the setup and maintenance of security configuration administrator and auditor accounts. Responsible for the maintenance of applications in the MAS.
- Security configuration administrator: Responsible for security configuration of the server, defining device user groups, setup and maintenance of device user group administrator accounts, and defining privileges of device user group administrators.
- Device user group administrator: Responsible for maintenance of mobile device accounts, including setup, change of account configurations, and account deletion. Responsible for defining which apps user groups or individual users have access to in the MAS. Can only perform administrative functions assigned by the security configuration administrator.
- Auditor: Responsible for reviewing and maintaining server and mobile device audit logs. 

Satisfies:FMT_SMR.1.1(1) 
Reference:PP-MDM-411058'
  desc 'check', 'Verify the UEM server has at least one user in defined administrator roles.

If the UEM server does not have at least one user in defined administrator roles, this is a finding.'
  desc 'fix', 'Configure the UEM server to have at least one user in defined administrator roles.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37660r615068_chk'
  tag severity: 'medium'
  tag gid: 'V-234475'
  tag rid: 'SV-234475r617355_rule'
  tag stig_id: 'SRG-APP-000329-UEM-000202'
  tag gtitle: 'SRG-APP-000329'
  tag fix_id: 'F-37625r615069_fix'
  tag 'documentable'
  tag cci: ['CCI-002169']
  tag nist: ['AC-3 (7)']
end
