control 'SV-243124' do
  title 'The vCenter Server must use a limited privilege account when adding an LDAP identity source.'
  desc 'When adding an LDAP identity source to vSphere SSO, the account used to bind to AD must be minimally privileged. This account only requires read rights to the base DN specified. Any other permissions inside or outside of that OU are unnecessary and violate least privilege.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign-On >> Configuration. 

Click the "Identity Sources" tab.

For each identity source with of type "Active Directory", highlight the item and click "Edit". 

If the account that is configured to bind to the LDAPS server is not one with minimal privileges, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign-On >> Configuration. 

Click the "Identity Sources" tab.

For each identity source that has been configured with a highly privileged AD account, highlight the item and click "Edit". 

Change the username and password to one with read-only rights to the base DN and complete the dialog.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46399r719613_chk'
  tag severity: 'medium'
  tag gid: 'V-243124'
  tag rid: 'SV-243124r879887_rule'
  tag stig_id: 'VCTR-67-000069'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46356r719614_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
