control 'SV-242659' do
  title 'The Cisco ISE must only allow authorized administrators to view or change the device configuration, system files, and other files stored.'
  desc 'This requirement is intended to address the confidentiality and integrity of system information at rest (e.g., network device rule sets) when it is located on a storage device within the network device or as a component of the network device. This protection is required to prevent unauthorized alteration, corruption, or disclosure of information when not stored directly on the network device.

Access to device configuration, system files, and other files stored locally are restricted to administrators by design. Admin accounts must be part of an administrator group and the group has associated authorizations based on role. There are 12 pre-defined admin roles and additional groups may be added.

By default, the username for a CLI admin user is admin, and the password is defined during setup. There is no default password. This CLI admin user is the default admin user, and this user account cannot be deleted. Create web administrator account as the Account of Last Resort and add to the default Super Admin group. This will allow at least one user to be able to delete other admins and perform special functions via the web management tool.'
  desc 'check', 'View the local admin users.

1. Choose Administration >> System >> Admin Access >> Administrators >> Admin Users >>View.
2. Verify there are only two local accounts are defined. Both must be in the Super User group. These users must be the web-based Account of Last Resort and the default CLI admin user.

If the Cisco ISE has unauthorized local users defined, this is a finding.'
  desc 'fix', 'Create a local web-based administrator. ONLY one web-based admin account should exist on the local device. The default CLI account is also local and cannot be removed.

1. Choose Administration >> System >> Admin Access >> Administrators >> Admin Users >> Add.
2. From the drop-down, choose "Create an Admin User".
3. Enter the admin name and other information. 
4. Add the Super User group.
5. Click "Submit".'
  impact 0.7
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45934r714285_chk'
  tag severity: 'high'
  tag gid: 'V-242659'
  tag rid: 'SV-242659r720805_rule'
  tag stig_id: 'CSCO-NM-000540'
  tag gtitle: 'SRG-APP-000231-NDM-000271'
  tag fix_id: 'F-45891r720804_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
