control 'SV-218723' do
  title 'If the system boots from removable media, it must be stored in a safe or similarly secured container.'
  desc 'Storing the boot loader on removable media in an insecure location could allow a malicious user to modify the systems boot instructions or boot to an insecure operating system.'
  desc 'check', 'Ask the SA if the system boots from removable media. If so, ask if the boot media is stored in a secure container when not in use. If it is not, this is a finding.'
  desc 'fix', 'Store the system boot media in a secure container when not in use.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20198r562945_chk'
  tag severity: 'high'
  tag gid: 'V-218723'
  tag rid: 'SV-218723r603259_rule'
  tag stig_id: 'GEN008680'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20196r562946_fix'
  tag 'documentable'
  tag legacy: ['V-4255', 'SV-63107']
  tag cci: ['CCI-000366', 'CCI-001208']
  tag nist: ['CM-6 b', 'SC-32']
end
