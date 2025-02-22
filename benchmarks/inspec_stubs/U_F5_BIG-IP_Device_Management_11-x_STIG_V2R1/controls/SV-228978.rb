control 'SV-228978' do
  title 'The BIG-IP appliance must provide automated support for account management functions.'
  desc "Account management functions include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The network device must be configured to automatically provide account management functions, and these functions must immediately enforce the organization's current account policy.

All accounts used for access to the network device are privileged or system-level accounts. Therefore, if account management functions are not automatically enforced, an attacker could gain privileged access to a vital element of the network security architecture.

This control does not include emergency administration accounts that provide access to the network device components in case of network failure. There must be only one such locally defined account.

All other accounts must be defined. All other accounts must be created and managed on the site's authentication server (e.g., RADIUS, LDAP, or Active Directory). This requirement is applicable to account management functions provided by the network device application. If the function is provided by the underlying OS or an authentication server, it must be secured using the applicable security guide or STIG."
  desc 'check', 'Verify the BIG-IP appliance is configured to use a remote authentication server that provides automated account management. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that provides automated support for account management functions.

If the BIG-IP appliance is not configured to use a remote authentication server to provide automated account management, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use an approved remote authentication server that provides automated support for account management.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31293r517981_chk'
  tag severity: 'medium'
  tag gid: 'V-228978'
  tag rid: 'SV-228978r557520_rule'
  tag stig_id: 'F5BI-DM-000013'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31270r517982_fix'
  tag 'documentable'
  tag legacy: ['V-60095', 'SV-74525']
  tag cci: ['CCI-000366', 'CCI-000015']
  tag nist: ['CM-6 b', 'AC-2 (1)']
end
