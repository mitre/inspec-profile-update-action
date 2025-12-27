control 'SV-234189' do
  title 'The FortiGate device must enforce access restrictions associated with changes to device configuration.'
  desc 'Failure to provide logical access restrictions associated with changes to device configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the device can potentially have significant effects on the overall security of the device.

Accordingly, only qualified and authorized individuals should be allowed to obtain access to device components for the purposes of initiating changes, including upgrades and modifications.

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Administrators.
3. Identify the administrator that is not authorized to access System Settings and hover over the profile assigned to the role.
4. Click Edit.
5. Verify the permission to System is set to Read or None.

If any unauthorized administrators have Read/Write access to System, this is a finding.'
  desc 'fix', 'To limit the System access to existing low-privileged administrators, log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Administrators.
3. Identify the admin role that has unauthorized access to System settings.
4. Select the admin role and hover over the profile assigned to the role.
5. Click Edit.
6. On System access permission, click None or Read only.
7. Click OK to save.

Repeat this process to define all the Administrators needed to meet privilege-separation requirements for the organization.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37374r611754_chk'
  tag severity: 'medium'
  tag gid: 'V-234189'
  tag rid: 'SV-234189r850527_rule'
  tag stig_id: 'FGFW-ND-000150'
  tag gtitle: 'SRG-APP-000380-NDM-000304'
  tag fix_id: 'F-37339r850526_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
