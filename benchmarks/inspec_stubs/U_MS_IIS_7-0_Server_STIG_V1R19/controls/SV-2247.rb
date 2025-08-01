control 'SV-2247' do
  title 'Only administrators are allowed access to the directory tree, the shell, or other operating system functions and utilities.'
  desc 'As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. This is in addition to the anonymous web user account. The resources to which these accounts have access must also be closely monitored and controlled. Only the SA needs access to all the system’s capabilities, while the web administrator and associated staff require access and control of the web content and web server configuration files. The anonymous web user account must not have access to system resources as that account could then control the server.'
  desc 'check', 'Obtain a list of the user accounts for the system, noting the priviledges for each account.  

Verify with the system administrator or the ISSO that all privileged accounts are mission essential and documented.

Verify with the system administrator or the ISSO that all non-administrator access to shell scripts and operating system functions are mission essential and documented.

If undocumented privileged accounts are found, this is a finding.

If undocumented access to shell scripts or operating system functions is found, this is a finding.'
  desc 'fix', 'Ensure non-administrators are not allowed access to the directory tree, the shell, or other operating system functions and utilities.'
  impact 0.7
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-29918r3_chk'
  tag severity: 'high'
  tag gid: 'V-2247'
  tag rid: 'SV-2247r4_rule'
  tag stig_id: 'WG200 W13'
  tag gtitle: 'WG200'
  tag fix_id: 'F-26806r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
