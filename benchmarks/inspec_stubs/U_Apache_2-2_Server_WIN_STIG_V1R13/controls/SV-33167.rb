control 'SV-33167' do
  title 'Active software modules must be minimized.'
  desc 'Modules are the source of Apache httpd servers core and dynamic capabilities. Thus not every module available is needed for operation. Most installations only need a small subset of the modules available. By minimizing the enabled modules to only those that are required, we reduce the number of doors and have therefore reduced the attack surface of the web site. Likewise having fewer modules means less software that could have vulnerabilities.'
  desc 'check', 'Open a command prompt window.

Navigate to the “bin” directory (in many cases this may be [Drive Letter]:\\[directory path]\\Apache Software Foundation\\Apache2.2\\bin>).

Enter the following command and press Enter: httpd –M

This will provide a list of the loaded modules. Discuss with the web administrator why all displayed modules are required for operation. If any module is not required for operation, this is a finding.

Note: The following modules do not need to be discussed: core_module, win32_module, mpm_winnt_module, http_module, so_module.'
  desc 'fix', 'Disable any modules that are not needed by adding a "#" in front of them within the httpd.conf file, and restarting the Apache httpd service.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33806r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26285'
  tag rid: 'SV-33167r1_rule'
  tag stig_id: 'WA00500 W22'
  tag gtitle: 'WA00500'
  tag fix_id: 'F-29455r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
