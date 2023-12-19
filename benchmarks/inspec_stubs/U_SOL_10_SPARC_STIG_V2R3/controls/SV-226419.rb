control 'SV-226419' do
  title 'The Solaris system EEPROM security-mode parameter must be set to full or command mode.'
  desc 'If the EEPROM security-mode parameter is not set to full or command, then unauthorized access to system EEPROM can take place.  In normal situations, when the system is in a controlled access area and it is desirable to have it automatically reboot upon loss of and restoring of power, for instance, then command mode with the autoboot parameter set to true is recommended.'
  desc 'check', 'If the system does not have an OBP / EEPROM, this is not applicable.

# eeprom | grep security-mode

If the EEPROM security-mode parameter is not set to full or command, this is a finding.'
  desc 'fix', 'Set the system EEPROM security-mode parameter to full or command.  

# eeprom security-mode=full
OR
# eeprom security-mode=command

The system will prompt the user for a password.  This should be securely stored.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28580r482618_chk'
  tag severity: 'medium'
  tag gid: 'V-226419'
  tag rid: 'SV-226419r603265_rule'
  tag stig_id: 'GEN000000-SOL00300'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28568r482619_fix'
  tag 'documentable'
  tag legacy: ['SV-958', 'V-958']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
