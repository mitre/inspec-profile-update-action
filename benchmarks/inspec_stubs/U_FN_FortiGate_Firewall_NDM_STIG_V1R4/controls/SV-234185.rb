control 'SV-234185' do
  title 'The FortiGate device must protect audit information from unauthorized deletion.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the network device must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include: ensuring log files receive the proper file system permissions utilizing file system protections, restricting access, and backing up log data to ensure log data is retained.

Network devices providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data, and the corresponding rights the user enjoys, to make access decisions regarding the deletion of audit data.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Administrators.
3. Click on each administrator who is not authorized to access Log and Report Settings and hover over the profile assigned to the role.
4. Click Edit.
5. Verify that the permission to Log and Report is set to None or Read.

If any low-privileged administrator has Read/Write access to Log and Report, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

To limit the Log and Report access to existing low-privileged administrators:

1. Click System.
2. Click Administrators.
3. Identify the admin role that has unauthorized access to Log and Report settings.
4. Select the admin role and hover over the profile assigned to the role.
5. Click Edit.
6. On Log and Report access permission, click None or Read.
7. Click OK to save.

Repeat this process to define all the Administrators needed to meet privilege separation requirements for the organization.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37370r611742_chk'
  tag severity: 'medium'
  tag gid: 'V-234185'
  tag rid: 'SV-234185r879578_rule'
  tag stig_id: 'FGFW-ND-000130'
  tag gtitle: 'SRG-APP-000120-NDM-000237'
  tag fix_id: 'F-37335r628866_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
