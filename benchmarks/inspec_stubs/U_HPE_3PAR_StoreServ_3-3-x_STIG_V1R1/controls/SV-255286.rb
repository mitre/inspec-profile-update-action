control 'SV-255286' do
  title 'The HPE 3PAR OS must map the authenticated identity to the user account for PKI-based authentication.'
  desc "Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.

PKI authentication is performed by the HPE 3PAR SSMC, and the authenticated user's identity is extracted from the certificate and forwarded to the HPE 3PAR OS over a mutually authenticated TLS channel. The HPE 3PAR OS then queries/authorizes the identity in the external Account Management system (LDAP/AD), and authorizes the individual as appropriate based on that. The ldap-2fa-cert-field is used to tell the SSMC which field to extract from the user certificate. The ldap-2fa-object-attr is used to search the account management system for an account with a matching attribute."
  desc 'check', 'Verify that the two factor authentication (2fa) parameters are set:

cli% showauthparam
If there is an error, or the output does not contain the following, this is a finding. 
ldap-2fa-cert-field <fieldName>
ldap-2fa-object-attr <ldap object corresponding to cert field>'
  desc 'fix', 'To configure the two factor authentication parameters (2fa) to support PKI based authentication/authorization:

cli% setauthparam -f ldap-2fa-cert-field <name of certificate field containing user identity string>

cli% setauthparam -f ldap-2fa-object-attr <attribute in ldap object corresponding to cert field value>'
  impact 0.7
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58959r870175_chk'
  tag severity: 'high'
  tag gid: 'V-255286'
  tag rid: 'SV-255286r870281_rule'
  tag stig_id: 'HP3P-33-004002'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag fix_id: 'F-58903r870176_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
