control 'SV-48379' do
  title 'The Telnet Client must not be installed on the system.'
  desc 'Some protocols and services do not support required security features, such as encrypting passwords or traffic.'
  desc 'check', 'Verify the Telnet Client has not been installed.  If Telnet.exe exists in the \\system32 directory, this is a finding.'
  desc 'fix', 'Uninstall "Telnet Client" from the system through "Turn Windows Features on or off".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45048r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36730'
  tag rid: 'SV-48379r2_rule'
  tag stig_id: 'WN08-GE-000024'
  tag gtitle: 'WN08-GE-000024'
  tag fix_id: 'F-41510r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
