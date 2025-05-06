control 'SV-234190' do
  title 'The FortiGate device must limit privileges to change the software resident within software libraries.'
  desc 'Changes to any software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals should be allowed administrative access to the network device for implementing any changes or upgrades. If the network device were to enable non-authorized users to make changes to software libraries, those changes could be implemented without undergoing testing, validation, and approval.'
  desc 'check', 'Log in to the FortiGate GUI with an Administrator that does not have System setting privileges.

1. Click System.
2. Attempt to click Firmware; this option will not be available.

If the FortiGate device does not limit privileges to change the software resident within software libraries, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

To remove System access permission from an existing low-privileged administrator:

1. Click System.
2. Click Administrators.
3. Identify the administrator role that is unauthorized to update software.
4. Select the administrator role and hover over the profile assigned to the role.
5. Click Edit.
6. For System access, click None.
7. Click OK to save.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37375r611757_chk'
  tag severity: 'medium'
  tag gid: 'V-234190'
  tag rid: 'SV-234190r628777_rule'
  tag stig_id: 'FGFW-ND-000155'
  tag gtitle: 'SRG-APP-000133-NDM-000244'
  tag fix_id: 'F-37340r611758_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
