control 'SV-77279' do
  title 'Riverbed Optimization System (RiOS) must provide automated support for account management functions.'
  desc "Account management functions include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The network device must be configured to automatically provide account management functions, and these functions must immediately enforce the organization's current account policy.

All accounts used for access to the network device are privileged or system-level accounts. Therefore, if account management functions are not automatically enforced, an attacker could gain privileged access to a vital element of the network security architecture.

This control does not include emergency administration accounts that provide access to the network device components in case of network failure. There must be only one such locally defined account.

All other accounts must be defined. All other accounts must be created and managed on the site's authentication server (e.g., RADIUS, LDAP, or Active Directory). This requirement is applicable to account management functions provided by the network device application. If the function is provided by the underlying OS or an authentication server, it must be secured using the applicable security guide or STIG."
  desc 'check', 'Verify that RiOS provides automated support for account management.

Navigate to the device Management Console
Navigate to:
Configure >> Security >> User Permissions

Verify user permissions are defined here.

If the account management is not set, this is a finding.'
  desc 'fix', 'Configure RiOS account management functions.

Navigate to the device Management Console, then
Navigate to:
Configure >> Security >> User Permissions

Set values for the user account.

Click "Save" to save these settings permanently.'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63597r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62789'
  tag rid: 'SV-77279r1_rule'
  tag stig_id: 'RICX-DM-000001'
  tag gtitle: 'SRG-APP-000023-NDM-000205'
  tag fix_id: 'F-68709r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
