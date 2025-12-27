control 'SV-36509' do
  title 'Administrators must be the only users allowed access to the directory tree, the shell, or other operating system functions and utilities.'
  desc 'As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. This is in addition to the anonymous web user account. The resources to which these accounts have access must also be closely monitored and controlled. Only the SA needs access to all the system’s capabilities, while the web administrator and associated staff require access and control of the web content and web server configuration files. The anonymous web user account must not have access to system resources as that account could then control the server.'
  desc 'check', 'Windows 2008 servers may be impacted by this check. If the SA or the web administrator can demonstrate that this requirement will adversely affect the web server by providing vendor documentation, this check is not applicable.

Search all of the system’s hard drives for the command.com and cmd.exe files. The allowed permissions on these files are:

System Full Control
Administrators Full Control

Examine account access and any group membership access to these files.

If any non-administrator account, group membership, or service ID has any access to any command.com or cmd.exe files and the access is documented as mission critical, this is not a finding.

Examine access to operating system configuration files, scripts, utilities, privileges, and functions.

If any non-administrator account, group membership, or service ID has any access to any of these operating system components and the access is documented as mission critical, this is not a finding.

If any non-administrator account, group membership, or service ID has undocumented access to any listed file or operating system component, this is a finding.'
  desc 'fix', 'Ensure non-administrators are not allowed access to the directory tree, the shell, or other operating system functions and utilities.'
  impact 0.7
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-35610r1_chk'
  tag severity: 'high'
  tag gid: 'V-2247'
  tag rid: 'SV-36509r1_rule'
  tag stig_id: 'WG200 W22'
  tag gtitle: 'WG200'
  tag fix_id: 'F-30844r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
