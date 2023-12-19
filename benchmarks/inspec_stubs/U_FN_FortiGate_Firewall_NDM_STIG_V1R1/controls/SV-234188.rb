control 'SV-234188' do
  title 'The FortiGate device must prohibit installation of software without explicit privileged status.'
  desc 'Allowing anyone to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. This requirement applies to code changes and upgrades for all network devices.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Administrators.
3. Identify the administrator that is not authorized to access System Settings and hover over the profile assigned to the role.
4. Click Edit.
5. Verify that the permission to System is set to Read or None.

If any unauthorized administrator has Read/Write access to System, this is a finding.'
  desc 'fix', 'To limit the System access to existing low-privileged administrators, log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Administrators.
3. Identify the admin role that has unauthorized access to System settings.
4. Select the admin role and hover over the profile assigned to the role.
5. Click Edit.
6. On System access permission, click None or Read only.
7. Click OK to save.

Repeat this process to define all the Administrators needed to meet privilege separation requirements for the organization.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37373r611751_chk'
  tag severity: 'medium'
  tag gid: 'V-234188'
  tag rid: 'SV-234188r628777_rule'
  tag stig_id: 'FGFW-ND-000145'
  tag gtitle: 'SRG-APP-000378-NDM-000302'
  tag fix_id: 'F-37338r611752_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
