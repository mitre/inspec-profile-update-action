control 'SV-234186' do
  title 'The FortiGate device must protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network devices providing tools to interface with audit data will leverage user permissions and roles, identifying the user accessing the tools and the corresponding rights the user enjoys, to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Administrators.
3. Click each administrator who is not authorized to access Log and Report Settings and hover over the profile assigned to the role.
4. Click Edit.
5. Verify the permission to Log and Report is set to None.

If any low-privileged administrator has Read/Write or Read access to Log and Report settings, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

To limit the Log and Report access to existing low-privileged administrators:

1. Click System.
2. Click Administrators.
3. Identify any administrator that is not authorized to access Log and Report settings.
4. Select the admin role and hover over the profile assigned to the role.
5. Click Edit.
6. On Log and Report access permission, click None.
7. Click OK to save.

Repeat this process to define all the Administrators needed to meet privilege-separation requirements for the organization.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37371r611745_chk'
  tag severity: 'medium'
  tag gid: 'V-234186'
  tag rid: 'SV-234186r628777_rule'
  tag stig_id: 'FGFW-ND-000135'
  tag gtitle: 'SRG-APP-000121-NDM-000238'
  tag fix_id: 'F-37336r611746_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
