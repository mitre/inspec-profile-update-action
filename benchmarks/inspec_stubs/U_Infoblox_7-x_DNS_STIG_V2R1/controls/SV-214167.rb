control 'SV-214167' do
  title 'The Infoblox system must be configured to employ strong authenticators in the establishment of nonlocal maintenance and diagnostic sessions.'
  desc "If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system. The act of managing systems and applications includes the ability to access sensitive application information, such as system configuration details, diagnostic information, user information, and potentially sensitive application data. 

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.

Lack of authentication enables anyone to gain access to the network or possibly a network element that provides opportunity for intruders to compromise resources within the network infrastructure. Network access control mechanisms interoperate to prevent unauthorized access and to enforce the organization's security policy. Authorization for access to any network element requires an individual account identifier that has been approved, assigned, and configured on an authentication server. Authentication of all administrator accounts for all privilege levels must be accomplished using two or more factors that include the following:

(i) something you know (e.g., password/PIN); 
(ii) something you have (e.g., cryptographic identification device, token); or 
(iii) something you are (e.g., biometric).

Infoblox systems support authentication using multiple authenticators including; LDAP, RADIUS, Microsoft Active Directory, OCSP, and local user database. Strong authentication can be enabled by implementation of two or more authentication forms."
  desc 'check', 'Review the configuration of external authentication methods to validate multi-factor authentication is enabled.

Navigate to Administration >> Administrators >> Authentication Policy.

Ensure multi factor authentication is enabled by validation that the multiple authentication methods are enabled and that local database is the last entry in the list.

When complete, click "Cancel" to exit the "Properties" screen.

If the aggregate authentication policy does not provide two or more factors, this is a finding.'
  desc 'fix', 'Navigate to Administration >> Authentication Server Groups.

Configure at least one remote authentication group (OCSP, TACACS+, RADIUS, LDAP, or Active Directory).

Navigate to Administration >> Administrators >> Authentication Policy.

Configure the remote authentication source as primary by placing it at the top of the list.
If necessary, move the Local User Database entry to the bottom of the list so it is utilized last.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15382r295767_chk'
  tag severity: 'medium'
  tag gid: 'V-214167'
  tag rid: 'SV-214167r612370_rule'
  tag stig_id: 'IDNS-7X-000200'
  tag gtitle: 'SRG-APP-000185-DNS-000021'
  tag fix_id: 'F-15380r295768_fix'
  tag 'documentable'
  tag legacy: ['V-68529', 'SV-83019']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
