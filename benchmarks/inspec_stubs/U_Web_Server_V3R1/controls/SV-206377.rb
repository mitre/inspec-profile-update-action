control 'SV-206377' do
  title 'The web server must provide install options to exclude the installation of documentation, sample code, example applications, and tutorials.'
  desc 'Web server documentation, sample code, example applications, and tutorials may be an exploitable threat to a web server because this type of code has not been evaluated and approved. A production web server must only contain components that are operationally necessary (e.g., compiled code, scripts, web-content, etc.). 

Any documentation, sample code, example applications, and tutorials must be removed from a production web server. To make certain that the documentation and code are not installed or uninstalled completely; the web server must offer an option as part of the installation process to exclude these packages or to uninstall the packages if necessary.'
  desc 'check', 'Review the web server documentation and deployment configuration to determine if the web server contains documentation, sample code, example applications, or tutorials.

Verify the web server install process also offers an option to exclude these elements from installation and provides an uninstall option for their removal.

If web server documentation, sample code, example applications, or tutorials are installed or the web server install process does not offer an option to exclude these elements from installation, this is a finding.'
  desc 'fix', 'Use the web server uninstall facility or manually remove any documentation, sample code, example applications, and tutorials.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6638r377723_chk'
  tag severity: 'medium'
  tag gid: 'V-206377'
  tag rid: 'SV-206377r395853_rule'
  tag stig_id: 'SRG-APP-000141-WSR-000077'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-6638r377724_fix'
  tag 'documentable'
  tag legacy: ['SV-54272', 'V-41695']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
