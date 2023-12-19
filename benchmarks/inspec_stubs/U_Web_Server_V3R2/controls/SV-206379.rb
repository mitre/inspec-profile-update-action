control 'SV-206379' do
  title 'The web server must provide install options to exclude installation of utility programs, services, plug-ins, and modules not necessary for operation.'
  desc 'Just as running unneeded services and protocols is a danger to the web server at the lower levels of the OSI model, running unneeded utilities and programs is also a danger at the application layer of the OSI model. Office suites, development tools, and graphical editors are examples of such programs that are troublesome. 

Individual productivity tools have no legitimate place or use on an enterprise, production web server and they are also prone to their own security risks. The web server installation process must provide options allowing the installer to choose which utility programs, services, and modules are to be installed or removed. By having a process for installation and removal, the web server is guaranteed to be in a more stable and secure state than if these services and programs were installed and removed manually.'
  desc 'check', 'Review the web server documentation and deployment configuration to determine which web server utilities, services, and modules are installed. Verify these options are essential to the operation of the web server. Also, confirm the web server install process offers an option to exclude these utilities, services, and modules from installation that are not needed for operation and that there is an uninstall option for their removal. 

If there are more utilities, services, or modules installed than are needed for the operation of the web server or the web server does not provide an install facility to customize installation, this is a finding.'
  desc 'fix', 'Use the web server uninstall facility or manually remove any utility programs, services, or modules not needed by the web server for operation.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6640r377729_chk'
  tag severity: 'medium'
  tag gid: 'V-206379'
  tag rid: 'SV-206379r879587_rule'
  tag stig_id: 'SRG-APP-000141-WSR-000080'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-6640r377730_fix'
  tag 'documentable'
  tag legacy: ['SV-54275', 'V-41698']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
