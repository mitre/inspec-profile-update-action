control 'SV-48381' do
  title 'The TFTP Client must not be installed on the system.'
  desc 'Some protocols and services do not support required security features, such as encrypting passwords or traffic.'
  desc 'check', 'Verify the TFTP Client has not been installed.  If TFTP.exe exists in the \\system32 directory, this is a finding.'
  desc 'fix', 'Uninstall "TFTP Client" from the system through "Turn Windows Features on or off".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45050r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36732'
  tag rid: 'SV-48381r2_rule'
  tag stig_id: 'WN08-GE-000026'
  tag gtitle: 'WN08-GE-000026'
  tag fix_id: 'F-41512r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
