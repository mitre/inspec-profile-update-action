control 'SV-227075' do
  title 'If the system boots from removable media, it must be stored in a safe or similarly secured container.'
  desc 'Storing the boot loader on removable media in an insecure location could allow a malicious user to modify the systems boot instructions or boot to an insecure operating system.'
  desc 'check', 'Ask the SA if the system boots from removable media. If so, ask if the boot media is stored in a secure container when not in use. If it is not, this is a finding.'
  desc 'fix', 'Store the system boot media in a secure container when not in use.'
  impact 0.7
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29237r485606_chk'
  tag severity: 'high'
  tag gid: 'V-227075'
  tag rid: 'SV-227075r603265_rule'
  tag stig_id: 'GEN008680'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29225r485607_fix'
  tag 'documentable'
  tag legacy: ['V-4255', 'SV-4255']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
