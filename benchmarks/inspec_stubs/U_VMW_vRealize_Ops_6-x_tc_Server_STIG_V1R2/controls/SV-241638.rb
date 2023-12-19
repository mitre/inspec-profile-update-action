control 'SV-241638' do
  title 'tc Server ALL must exclude installation of utility programs, services, plug-ins, and modules not necessary for operation.'
  desc 'Just as running unneeded services and protocols is a danger to the web server at the lower levels of the OSI model, running unneeded utilities and programs is also a danger at the application layer of the OSI model. Office suites, development tools, and graphical editors are examples of such programs that are troublesome.

Because tc Server is installed as part of the entire vROps application, and not installed separately, VMware has ensured that no unnecessary utilities and programs have been included in tc Server.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Review the web server documentation and deployed configuration to determine if utility programs, services, plug-ins, and modules not necessary for operation have been removed.

If utility programs, services, plug-ins, and modules not necessary for operation have not been removed, this is a finding.'
  desc 'fix', 'Document the removal of all utility programs, services, plug-ins, and modules not necessary for operation and ensure the web server configuration does not contain any utility programs, services, plug-ins, and modules not necessary for operation.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44914r684149_chk'
  tag severity: 'medium'
  tag gid: 'V-241638'
  tag rid: 'SV-241638r879587_rule'
  tag stig_id: 'VROM-TC-000365'
  tag gtitle: 'SRG-APP-000141-WSR-000080'
  tag fix_id: 'F-44873r683775_fix'
  tag 'documentable'
  tag legacy: ['SV-99561', 'V-88911']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
