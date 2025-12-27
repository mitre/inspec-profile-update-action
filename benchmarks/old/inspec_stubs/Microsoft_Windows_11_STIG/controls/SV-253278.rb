control 'SV-253278' do
  title 'The Telnet Client must not be installed on the system.'
  desc 'The "Telnet Client" is not installed by default. Some protocols and services do not support required security features, such as encrypting passwords or traffic.'
  desc 'check', 'Verify Telnet Client has not been installed.

Navigate to the Windows\\System32 directory.

If the "telnet" application exists, this is a finding.'
  desc 'fix', 'Uninstall "Telnet Client" from the system.

Run "Programs and Features".
Select "Turn Windows Features on or off".

De-select "Telnet Client".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56731r828916_chk'
  tag severity: 'medium'
  tag gid: 'V-253278'
  tag rid: 'SV-253278r828918_rule'
  tag stig_id: 'WN11-00-000115'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-56681r828917_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
