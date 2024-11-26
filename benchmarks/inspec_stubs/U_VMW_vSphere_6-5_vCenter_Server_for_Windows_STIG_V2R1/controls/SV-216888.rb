control 'SV-216888' do
  title 'The vCenter Server for Windows must use a limited privilege account when adding an LDAP identity source.'
  desc 'When adding an LDAP identity source to vSphere SSO the account used to bind to AD must be minimally privileged. This account only requires read rights to the base DN specified. Any other permissions inside or outside of that OU are unnecessary and violate least privilege.'
  desc 'check', 'Note: This requirement is applicable for Active Directory over LDAP connections and Not Applicable when the vCenter or PSC server is joined to AD and using integrated windows authentication.

From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration. 

Click the "Identity Sources" tab.

For each identity source with of type "Active Directory", highlight the item and click the pencil icon to open the edit dialog. 

If the account that is configured to bind to the LDAP server is not one with minimal privileges, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration. 

Click the "Identity Sources" tab.

For each identity source that has been configured with a highly privileged AD account, highlight the item and click the pencil icon to open the edit dialog. Change the username and password to one with read only rights to the base DN and complete the dialog.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18119r531365_chk'
  tag severity: 'medium'
  tag gid: 'V-216888'
  tag rid: 'SV-216888r612237_rule'
  tag stig_id: 'VCWN-65-000069'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18117r366379_fix'
  tag 'documentable'
  tag legacy: ['V-94841', 'SV-104671']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
