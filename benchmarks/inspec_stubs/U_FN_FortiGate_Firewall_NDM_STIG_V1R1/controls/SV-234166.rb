control 'SV-234166' do
  title 'The FortiGate device must allow full access to only those individuals or roles designated by the ISSM.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data. 

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Administrators.
3. Identify the administrator who is authorized to access System Settings and hover over the profile assigned to the role.
4. Click Edit.
5. Verify that the permission to System is set to Read/Write.

Then,
1. Click System.
2. Click Administrators.
3. Click other administrators and hover over the profile assigned to the role.
4. Click Edit.
5. Verify that the permission to System is set to Read or None.

If any low-privileged administrator not designated by the ISSM has Read/Write access to System, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

First, set a single admin profile with full System access.
1. Click System.
2. Click Admin Profiles.
3. Click +Create New (Admin Profile).
4. Assign a meaningful name to the Profile.
5. Set System Access Permissions to Read/Write.
6. Click OK to save this Profile.

Then, 
1. Click System.
2. Click Administrators.
3. Click +Create New (Administrator).
4. Configure Administrator settings with unique Username, Type, and Password.
5. While assigning the Administrator Profile, use the Admin profile configured above with full access to System settings.
6. Go to Restrict login to trusted hosts.
7. Add appropriate IP address in the field Trusted Host 1.
8. Click OK to save.

Note: Do not assign this admin profile to any users other than designated administrators that are allowed full access to System Settings.

To limit the System access to existing low-privilege administrators:

1. Click System.
2. Click Administrators.
3. Identify the admin role that has unauthorized access to System settings.
4. Select the admin role and hover over the profile assigned to the role.
4. Click Edit.
5. On System access permission, click None.
6. Go to Restrict login to trusted hosts.
7. Add appropriate IP address in the field Trusted Host 1.
8. Click OK to save.

Repeat this process to define all the Administrators needed to meet privilege separation requirements for the organization.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37351r611685_chk'
  tag severity: 'medium'
  tag gid: 'V-234166'
  tag rid: 'SV-234166r628777_rule'
  tag stig_id: 'FGFW-ND-000035'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-37316r611686_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
