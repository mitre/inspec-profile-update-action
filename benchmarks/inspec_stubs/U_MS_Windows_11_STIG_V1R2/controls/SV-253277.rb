control 'SV-253277' do
  title 'Simple TCP/IP Services must not be installed on the system.'
  desc '"Simple TCP/IP Services" is not installed by default. Some protocols and services do not support required security features, such as encrypting passwords or traffic.'
  desc 'check', 'Verify Simple TCP/IP Services has not been installed.

Run "Services.msc".

If "Simple TCP/IP Services" is listed, this is a finding.'
  desc 'fix', 'Uninstall "Simple TCPIP Services (i.e. echo, daytime etc.)" from the system.

Run "Programs and Features".
Select "Turn Windows Features on or off".
De-select "Simple TCPIP Services (i.e. echo, daytime etc.)".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56730r828913_chk'
  tag severity: 'medium'
  tag gid: 'V-253277'
  tag rid: 'SV-253277r828915_rule'
  tag stig_id: 'WN11-00-000110'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56680r828914_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
