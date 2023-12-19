control 'SV-83765' do
  title 'The NSX vCenter must be configured to use an authentication server to provide automated support for account management functions to centrally control the authentication process for the purpose of granting administrative access.'
  desc "Account management functions include: assignment of group or role membership; identifying account type; specifying user access authorizations and privilege levels. NSX Manager must be configured to automatically provide account management functions, and these functions must immediately enforce the organization's current account policy. All accounts used for access to the NSX components are privileged or system-level accounts. Therefore, if account management functions are not automatically enforced, an attacker could gain privileged access to a vital element of the network security architecture.

With the exception of the account of last resort, all accounts must be created and managed on the site's authentication server (e.g., RADIUS, LDAP, or Active Directory). This requirement is applicable to account management functions provided by the network device."
  desc 'check', 'Verify the Windows server hosting vCenter is joined to the domain and access to the server and vCenter is done using Active Directory accounts.

If the vCenter server is not joined to an Active Directory domain, this is a finding.

If Active Directory-based accounts are not used for daily operations of the vCenter server, this is a finding.

If Active Directory is not used in the environment, this is not applicable.'
  desc 'fix', 'If the server hosting vCenter is not joined to the domain, follow the OS-specific procedures to join it to Active Directory.

If local accounts are used for normal operations, Active Directory accounts should be created and used.'
  impact 0.7
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69599r1_chk'
  tag severity: 'high'
  tag gid: 'V-69161'
  tag rid: 'SV-83765r1_rule'
  tag stig_id: 'VNSX-ND-000006'
  tag gtitle: 'SRG-APP-000023-NDM-000205'
  tag fix_id: 'F-75347r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
