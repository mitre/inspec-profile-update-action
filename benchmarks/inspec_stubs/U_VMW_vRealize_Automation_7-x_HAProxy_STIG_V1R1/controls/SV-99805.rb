control 'SV-99805' do
  title 'HAProxy must not contain any documentation, sample code, example applications, and tutorials.'
  desc 'Web server documentation, sample code, example applications, and tutorials may be an exploitable threat to a web server because this type of code has not been evaluated and approved. A production web server must only contain components that are operationally necessary (e.g., compiled code, scripts, web-content, etc.). 

Any documentation, sample code, example applications, and tutorials must be removed from a production web server. To make certain that the documentation and code are not installed or uninstalled completely; the web server must offer an option as part of the installation process to exclude these packages or to uninstall the packages if necessary.'
  desc 'check', 'At the command prompt, execute the following command:

ls /usr/share/doc/packages/haproxy

The command should report that there is no such file or directory. 

If the command shows any files or directories, this is a finding.'
  desc 'fix', 'Remove all listed files and directories.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88847r2_chk'
  tag severity: 'high'
  tag gid: 'V-89155'
  tag rid: 'SV-99805r1_rule'
  tag stig_id: 'VRAU-HA-000140'
  tag gtitle: 'SRG-APP-000141-WSR-000077'
  tag fix_id: 'F-95897r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
