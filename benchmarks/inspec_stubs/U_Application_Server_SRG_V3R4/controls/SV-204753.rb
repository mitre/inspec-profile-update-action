control 'SV-204753' do
  title 'The application server must utilize encryption when using LDAP for authentication.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission. 

Application servers have the capability to utilize LDAP directories for authentication. If LDAP connections are not protected during transmission, sensitive authentication credentials can be stolen. When the application server utilizes LDAP, the LDAP traffic must be encrypted.'
  desc 'check', 'Review application server documentation and configuration to determine if the application server enforces the requirement to encrypt LDAP traffic.

If the application server is not configured to meet this requirement, this is a finding.'
  desc 'fix', 'Configure the application server to encrypt LDAP traffic.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4873r282906_chk'
  tag severity: 'medium'
  tag gid: 'V-204753'
  tag rid: 'SV-204753r879609_rule'
  tag stig_id: 'SRG-APP-000172-AS-000121'
  tag gtitle: 'SRG-APP-000172'
  tag fix_id: 'F-4873r282907_fix'
  tag 'documentable'
  tag legacy: ['V-35319', 'SV-46606']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
