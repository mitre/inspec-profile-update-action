control 'SV-240239' do
  title 'Lighttpd must only contain components that are operationally necessary.'
  desc 'Web server documentation, sample code, example applications, and tutorials may be an exploitable threat to a web server because this type of code has not been evaluated and approved. A production web server must only contain components that are operationally necessary (e.g., compiled code, scripts, web-content, etc.). 

Any documentation, sample code, example applications, and tutorials must be removed from a production web server. To make certain that the documentation and code are not installed or uninstalled completely; the web server must offer an option as part of the installation process to exclude these packages or to uninstall the packages if necessary.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Determine if web server documentation, sample code, example applications, or tutorials has been deleted or removed and only contains components that are operationally necessary.

If web server documentation, sample code, example applications, or tutorials has not been deleted or removed and contains components that are not operationally necessary, this is a finding.'
  desc 'fix', 'Delete or remove any documentation, sample code, example applications, tutorials and any components that are not operationally necessary.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43472r668011_chk'
  tag severity: 'high'
  tag gid: 'V-240239'
  tag rid: 'SV-240239r879587_rule'
  tag stig_id: 'VRAU-LI-000170'
  tag gtitle: 'SRG-APP-000141-WSR-000077'
  tag fix_id: 'F-43431r667893_fix'
  tag 'documentable'
  tag legacy: ['SV-99909', 'V-89259']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
