control 'SV-253279' do
  title 'The TFTP Client must not be installed on the system.'
  desc 'The "TFTP Client" is not installed by default. Some protocols and services do not support required security features, such as encrypting passwords or traffic.'
  desc 'check', 'Verify TFTP Client has not been installed.

Navigate to the Windows\\System32 directory.

If the "TFTP" application exists, this is a finding.'
  desc 'fix', 'Uninstall "TFTP Client" from the system.

Run "Programs and Features".
Select "Turn Windows Features on or off".
De-select "TFTP Client".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56732r828919_chk'
  tag severity: 'medium'
  tag gid: 'V-253279'
  tag rid: 'SV-253279r828921_rule'
  tag stig_id: 'WN11-00-000120'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-56682r828920_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
