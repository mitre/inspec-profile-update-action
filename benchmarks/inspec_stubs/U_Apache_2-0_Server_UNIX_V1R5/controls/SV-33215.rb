control 'SV-33215' do
  title 'Active software modules must be minimized.'
  desc 'Modules are the source of Apache httpd servers core and dynamic capabilities. Thus not every module available is needed for operation. Most installations only need a small subset of the modules available. By minimizing the enabled modules to only those that are required, we reduce the number of doors and have therefore reduced the attack surface of the web site. Likewise having fewer modules means less software that could have vulnerabilities.'
  desc 'check', 'Enter the following command:

/usr/local/Apache2.2/bin/httpd –M

This will provide a list of the loaded modules. Validate that all displayed modules are required for operations. If any module is not required for operation, this is a finding.

Note:  The following modules are needed for basic web function and do not need to be reviewed:  

core_module
http_module
so_module
mpm_prefork_module'
  desc 'fix', 'Disable any modules that are not needed.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33753r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26285'
  tag rid: 'SV-33215r1_rule'
  tag stig_id: 'WA00500 A22'
  tag gtitle: 'WA00500'
  tag fix_id: 'F-29389r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'DCSQ-1, DCSW-1'
end
