control 'SV-218797' do
  title 'The IIS 10.0 web server must be reviewed on a regular basis to remove any Operating System features, utility programs, plug-ins, and modules not necessary for operation.'
  desc 'Just as running unneeded services and protocols is a danger to the web server at the lower levels of the OSI model, running unneeded utilities and programs is a danger at the application layer of the OSI model. Office suites, development tools, and graphic editors are examples of such troublesome programs.

Individual productivity tools have no legitimate place or use on an enterprise production web server and are prone to security risks. The web server installation process must provide options allowing the installer to choose which utility programs, services, and modules are to be installed or removed. By having a process for installation and removal, the web server is guaranteed to be in a more stable and secure state than if these services and programs were installed and removed manually.'
  desc 'check', 'Consult with the System Administrator and review all of the IIS 10.0 and Operating System features installed.

Determine if any features installed are no longer necessary for operation.

If any utility programs, features, or modules are installed which are not necessary for operation, this is a finding.

If any unnecessary Operating System features are installed, this is a finding.'
  desc 'fix', 'Remove all utility programs, Operating System features, or modules installed that are not necessary for web server operation.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20269r310866_chk'
  tag severity: 'medium'
  tag gid: 'V-218797'
  tag rid: 'SV-218797r561041_rule'
  tag stig_id: 'IIST-SV-000123'
  tag gtitle: 'SRG-APP-000141-WSR-000080'
  tag fix_id: 'F-20267r310867_fix'
  tag 'documentable'
  tag legacy: ['SV-109233', 'V-100129']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
