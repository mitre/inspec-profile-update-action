control 'SV-254112' do
  title 'Nutanix AOS must utilize encryption when using LDAP for authentication.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission. 

Application servers have the capability to utilize LDAP directories for authentication. If LDAP connections are not protected during transmission, sensitive authentication credentials can be stolen. When the application server utilizes LDAP, the LDAP traffic must be encrypted.'
  desc 'check', 'Confirm Nutanix AOS is set to use encryption when using LDAP.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to the Authentication settings.
4. Add an Active Directory or OpenLDAP server to the Directory List.

If an Active Directory or OpenLDAP server is not using port 636, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS to utilize an Active Directory server to authenticate individual users.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to the Authentication settings.
4. Add an Active Directory or OpenLDAP server to the Directory List utilizing SSL encrypted port 636.'
  impact 0.7
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57597r858125_chk'
  tag severity: 'high'
  tag gid: 'V-254112'
  tag rid: 'SV-254112r858125_rule'
  tag stig_id: 'NUTX-AP-000340'
  tag gtitle: 'SRG-APP-000172-AS-000121'
  tag fix_id: 'F-57548r846423_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
