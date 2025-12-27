control 'SV-243123' do
  title 'The vCenter Server must use secure Lightweight Directory Access Protocol (LDAPS) when adding an SSO identity source.'
  desc 'LDAP is an industry-standard protocol for querying directory services such as Active Directory. This protocol can operate in clear text or over an SSL/TLS encrypted tunnel. 

To protect confidentiality of LDAP communications, secure LDAP (LDAPS) must be explicitly configured when adding an LDAP identity source in vSphere SSO. When configuring an identity source and supplying an SSL certificate, vCenter will enforce LDAPs. The server URLs do not need to be explicitly provided as long as an SSL certificate is uploaded.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign-On >> Configuration. 

Click the "Identity Sources" tab.

For each identity source of type "Active Directory", if the "Server URL" does not indicate "ldaps://", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign-On >> Configuration. 

Click the "Identity Sources" tab.

For each identity source of type "Active Directory" where LDAPS is not configured, highlight the item and click "Edit". 

Ensure the primary and secondary server URLs, if specified, are configured for "ldaps://". 

At the bottom, click the "Browse" button, select the AD LDAP cert previously exported to the local computer, click "Open", and "Save" to complete modifications.

Note: With LDAPS, the server must be a specific domain controller and its specific certificate or the domain alias with a certificate that is valid for that URL.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46398r719610_chk'
  tag severity: 'medium'
  tag gid: 'V-243123'
  tag rid: 'SV-243123r879887_rule'
  tag stig_id: 'VCTR-67-000068'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46355r719611_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
