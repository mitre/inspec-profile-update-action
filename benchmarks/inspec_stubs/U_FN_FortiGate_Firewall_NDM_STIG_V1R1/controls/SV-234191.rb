control 'SV-234191' do
  title 'The FortiGate device must enforce access restrictions associated with changes to the system components.'
  desc 'Changes to the hardware or software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals should be allowed administrative access to the network device for implementing any changes or upgrades. This requirement applies to updates of the application files, configuration, ACLs, and policy filters.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Administrators.
3. Identify the administrator who is authorized to access System Settings and hover over the profile assigned to the role.
4. Click Edit.
5. Verify that the permission to System is set to Read/Write.

If the authorized administrator does not have Read/Write access to System, this is a finding.

Then, 
1. Click System.
2. Click Administrators.
3. Click other administrators and hover over the profile assigned to the role.
4. Click Edit.
5. Verify that the permission to System is set to Read or None.

If any low-privileged administrator has Read/Write access to System, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

Set one admin profile with full System access.

1. Click System.
2. Click Admin Profiles.
3. Click +Create New (Admin Profile).
4. Assign a meaningful name to the Profile.
5. Set System Access Permissions to Read/Write.
6. Click OK to save this Profile.

Then, 
1. Click System.
2. Click Administrators.
3. Click on +Create New (Administrator).
4. Configure Administrator settings with unique Username, Type, and Password.
5. While assigning the Administrator Profile, use the Admin profile configured above with limited access to System settings.
6. Go to Restrict login to trusted hosts.
7. Add appropriate IP address in the field Trusted Host 1.
8. Click OK to save.
 
Note: Do not assign this admin profile to any users other than designated administrator that can have full access to System Settings.

To limit the System access to existing low-privilege administrators: 

1. Click System.
2. Click Administrators.
3. Identify the admin role that has unauthorized access to System settings.
4. Select the admin role and hover over the profile assigned to the role.
5. Click Edit.
6. On System access permission, click None or Read only.
7. Go to Restrict login to trusted hosts.
8. Add appropriate IP address in the field Trusted Host 1.
9. Click OK to save.

Repeat this process to define all the Administrators needed to meet privilege separation requirements for the organization.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37376r611760_chk'
  tag severity: 'medium'
  tag gid: 'V-234191'
  tag rid: 'SV-234191r628777_rule'
  tag stig_id: 'FGFW-ND-000160'
  tag gtitle: 'SRG-APP-000516-NDM-000335'
  tag fix_id: 'F-37341r611761_fix'
  tag 'documentable'
  tag cci: ['CCI-000345', 'CCI-000366']
  tag nist: ['CM-5', 'CM-6 b']
end
