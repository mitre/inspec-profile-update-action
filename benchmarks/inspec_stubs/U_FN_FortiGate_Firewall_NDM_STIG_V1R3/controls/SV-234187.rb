control 'SV-234187' do
  title 'The FortiGate device must protect audit tools from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network devices providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools, and the corresponding rights the user enjoys, to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Administrators.
3. Click on each administrator who is not authorized to access Log and Report settings and hover over the profile assigned to the role.
4. Click Edit.
5. Verify that the permission to Log and Report is set to None or Read.

If any low-privileged administrator has Read/Write access to Log and Report, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

To limit the Log and Report access to existing low-privileged administrators:

1. Click System.
2. Click Administrators.
3. Identify the admin role that is not authorized access to Log and Report settings.
4. Select the admin role and hover over the profile assigned to the role.
5. Click Edit.
6. On Log and Report access permission, click None or Read.
7. Click OK to save.

Repeat this process to define all the Administrators needed to meet privilege separation requirements for the organization.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37372r611748_chk'
  tag severity: 'medium'
  tag gid: 'V-234187'
  tag rid: 'SV-234187r628869_rule'
  tag stig_id: 'FGFW-ND-000140'
  tag gtitle: 'SRG-APP-000122-NDM-000239'
  tag fix_id: 'F-37337r628868_fix'
  tag 'documentable'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
