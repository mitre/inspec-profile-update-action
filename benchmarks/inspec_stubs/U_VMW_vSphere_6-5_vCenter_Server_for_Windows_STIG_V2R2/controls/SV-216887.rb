control 'SV-216887' do
  title 'The vCenter Server for Windows must use LDAPS when adding an SSO identity source.'
  desc 'LDAP (Lightweight Directory Access Protocol) is an industry standard protocol for querying directory services such as Active Directory. This protocol can operate in clear text or over an SSL/TLS encrypted tunnel. To protect confidentiality of LDAP communications the LDAPS option must be selected when adding an LDAP identity source in vSphere SSO.'
  desc 'check', 'Note: This requirement is applicable for Active Directory over LDAP connections and Not Applicable when the vCenter or PSC server is joined to AD and using integrated windows authentication.

From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration. 

Click the "Identity Sources" tab.

For each identity source of type "Active Directory", highlight the item and click the pencil icon to open the edit dialog. 

If the LDAPs box at the bottom is not checked, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration. 

Click the "Identity Sources" tab.

For each identity source of type "Active Directory" where LDAPS is not configured, highlight the item and click the pencil icon to open the edit dialog. Check the box at the bottom for LDAPS and click "Next". Click the green plus button to upload the trusted DC certificate or click the magnifying glass to extract the certificate from the DC directly. Click "Next". Click "Finish".'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18118r531363_chk'
  tag severity: 'medium'
  tag gid: 'V-216887'
  tag rid: 'SV-216887r612237_rule'
  tag stig_id: 'VCWN-65-000068'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18116r366376_fix'
  tag 'documentable'
  tag legacy: ['SV-104669', 'V-94839']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
