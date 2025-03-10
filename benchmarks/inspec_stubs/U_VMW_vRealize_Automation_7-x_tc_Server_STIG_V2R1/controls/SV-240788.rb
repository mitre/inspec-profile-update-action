control 'SV-240788' do
  title 'tc Server ALL must exclude installation of utility programs, services, plug-ins, and modules not necessary for operation.'
  desc 'Just as running unneeded services and protocols is a danger to the web server at the lower levels of the OSI model, running unneeded utilities and programs is also a danger at the application layer of the OSI model. Office suites, development tools, and graphical editors are examples of such programs that are troublesome. 

Because tc Server is installed as part of the entire vRA application, and not installed separately, VMware has ensured that no unnecessary utilities and programs have been included in tc Server.'
  desc 'check', 'Interview the ISSO.

Review the web server documentation and deployed configuration to determine if utility programs, services, plug-ins, and modules not necessary for operation have been removed.

If utility programs, services, plug-ins, and modules not necessary for operation have not been removed, this is a finding.'
  desc 'fix', 'Remove all utility programs, services, plug-ins, and modules not necessary for operation.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44021r674469_chk'
  tag severity: 'medium'
  tag gid: 'V-240788'
  tag rid: 'SV-240788r674470_rule'
  tag stig_id: 'VRAU-TC-000355'
  tag gtitle: 'SRG-APP-000141-WSR-000080'
  tag fix_id: 'F-43980r674107_fix'
  tag 'documentable'
  tag legacy: ['SV-100995', 'V-90345']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
