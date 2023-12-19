control 'SV-48380' do
  title 'Telnet Server must not be installed on the system.'
  desc 'Some protocols and services do not support required security features, such as encrypting passwords or traffic.'
  desc 'check', 'Verify Telnet Server has not been installed.  If TlntSvr.exe exists in the \\system32 directory, this is a finding.'
  desc 'fix', 'Uninstall "Telnet Server" from the system through "Turn Windows Features on or off".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45049r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36731'
  tag rid: 'SV-48380r2_rule'
  tag stig_id: 'WN08-GE-000025'
  tag gtitle: 'WN08-GE-000025'
  tag fix_id: 'F-41511r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
