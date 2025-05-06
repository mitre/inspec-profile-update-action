control 'SV-48378' do
  title 'Simple TCP/IP Services must not be installed on the system.'
  desc 'Some protocols and services do not support required security features, such as encrypting passwords or traffic.'
  desc 'check', 'Verify "Simple TCP/IP Services" has not been installed on the system. 
Run "Services.msc".
If "Simple TCP/IP Services" is listed, this is a finding.'
  desc 'fix', 'Uninstall "Simple TCPIP Services (i.e. echo, daytime etc)" from the system through "Turn Windows features on or off".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-51815r2_chk'
  tag severity: 'medium'
  tag gid: 'V-36729'
  tag rid: 'SV-48378r3_rule'
  tag stig_id: 'WN08-GE-000023'
  tag gtitle: 'WN08-GE-000023'
  tag fix_id: 'F-41509r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
