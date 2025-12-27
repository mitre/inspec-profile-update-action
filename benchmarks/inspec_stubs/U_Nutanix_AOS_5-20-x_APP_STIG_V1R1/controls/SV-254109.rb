control 'SV-254109' do
  title 'Nutanix AOS must use an enterprise user management system to uniquely identify and authenticate users.'
  desc 'To ensure accountability and prevent unauthorized access, application server users must be uniquely identified and authenticated. This is typically accomplished via the use of a user store which is either local (OS-based) or centralized (LDAP) in nature.

To ensure support to the enterprise, the authentication must utilize an enterprise solution.'
  desc 'check', 'Verify that Nutanix AOS is set to use enterprise user management systems.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to the "Authentication" settings.

If an Active Directory or OpenLDAP server is not configured, this is a finding.

Verify that only one local user account exists as the account of last resort.

Navigate to Local User Management.

If more than one local user account exists, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS to use an enterprise user management system to authenticate individual users.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to the Authentication settings.
4. Add an Active Directory or OpenLDAP server to the Directory List.

Configure one local admin user as the account of last resort.

1. Log in to Prism Element.
2.  Click on the gear icon in the upper right.
3.  Navigate to "Local User Management".
4.  Select "+ New Users".'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57594r858122_chk'
  tag severity: 'medium'
  tag gid: 'V-254109'
  tag rid: 'SV-254109r858122_rule'
  tag stig_id: 'NUTX-AP-000270'
  tag gtitle: 'SRG-APP-000148-AS-000101'
  tag fix_id: 'F-57545r846414_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
