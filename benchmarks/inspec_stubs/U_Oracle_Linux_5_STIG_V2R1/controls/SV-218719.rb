control 'SV-218719' do
  title 'The system must be configured to only boot from the system boot device.'
  desc 'The ability to boot from removable media is the same as being able to boot into single user, or maintenance, mode without a password. This ability could allow a malicious user to boot the system and perform changes with the potential to compromise or damage the system. It could also allow the system to be used for malicious purposes by a malicious anonymous user.'
  desc 'check', 'Determine if the system is configured to boot from devices other than the system startup media. If so, this is a finding.'
  desc 'fix', 'Configure the system to only boot from system startup media.

Procedure:
On systems with a BIOS or system controller use the BIOS interface at startup to remove all but the proper boot device from the boot device list.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20194r556574_chk'
  tag severity: 'high'
  tag gid: 'V-218719'
  tag rid: 'SV-218719r603259_rule'
  tag stig_id: 'GEN008600'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20192r556575_fix'
  tag 'documentable'
  tag legacy: ['V-1013', 'SV-63139']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
