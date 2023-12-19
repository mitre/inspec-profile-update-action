control 'SV-252197' do
  title 'The HPE Nimble must be configured to use an authentication server for the purpose of authenticating users prior to granting administrative access.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Run the command "userauth --list". If the output is "No domains configured", this is a finding.'
  desc 'fix', 'To configure AD, run the following commands: 

"userauth --join <domain> --domain_user administrator" and enter the domain administrator password to join <domain>. 

"userauth --list" will show the domain and its status. 

To create a mapping between an AD group and one of the four device RBAC roles, run the following command: 

"userauth --add_group <domain_group> --domain <domain> --role {administrator|poweruser|operator|guest}"

This command allows any member of <domain_group> in <domain> AD domain to log in to the device with one of the selected roles. 

To display the group to role mappings, run "userauth --list_group --domain <domain>".'
  impact 0.7
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55653r814069_chk'
  tag severity: 'high'
  tag gid: 'V-252197'
  tag rid: 'SV-252197r814071_rule'
  tag stig_id: 'HPEN-NM-000120'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-55603r814070_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
