control 'SV-246823' do
  title 'If the HYCU Server or Web UI uses discretionary access control, the network device must enforce organization-defined discretionary access control policies over defined subjects and objects.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual network administrators are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

'
  desc 'check', "HYCU offers the capability to leverage RBAC controls within the Web UI's Self-Service menu. The organization would need to generate and document its own specific requirements around using RBAC in HYCU. 

For the HYCU VM console, administrators should only allow access to anyone else deemed to be qualified as a server administrator for the system. 

Review the groups and accounts within Web UI's Self-Service menu.

If any RBAC setting does not meet the organization's own guidelines, this is a finding."
  desc 'fix', %q(Ensure the correct RBAC controls and access are applied properly within the HYCU Web UI's Self-Service menu. Avoid granting too much access to any particular user or group. 

Ensure that any needed DACLs are also being applied to and enforced on any OUs or groups in Active Directory that are being leveraged within the HYCU Web UI Self-Service menu. 

For the HYCU VM console, administrators should only allow access to anyone else deemed to be qualified as a server administrator for the system. 

To check for any unauthorized users, run the following command within the HYCU Web console: 
cat /etc/passwd

Use the "userdel" command to remove any unauthorized users.)
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50255r768131_chk'
  tag severity: 'medium'
  tag gid: 'V-246823'
  tag rid: 'SV-246823r768133_rule'
  tag stig_id: 'HYCU-AC-000005'
  tag gtitle: 'SRG-APP-000328-NDM-000286'
  tag fix_id: 'F-50209r768132_fix'
  tag satisfies: ['SRG-APP-000328-NDM-000286', 'SRG-APP-000329-NDM-000287']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002165', 'CCI-002169']
  tag nist: ['CM-6 b', 'AC-3 (4)', 'AC-3 (7)']
end
