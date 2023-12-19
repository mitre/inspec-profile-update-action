control 'SV-250613' do
  title 'If the system boots from removable media, it must be stored in a safe or similarly secured container.'
  desc 'Storing the boot loader on removable media in an insecure location could allow a malicious user to modify the systems boot instructions or boot to an insecure operating system.'
  desc 'check', 'Ask the SA if the system boots from removable media. If so, ask if the boot media is stored in a secure container when not in use. 

If  boot media is not stored in a secure container when not in use, this is a finding.'
  desc 'fix', 'Store the system boot media in a secure container when not in use.'
  impact 0.7
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54048r798836_chk'
  tag severity: 'high'
  tag gid: 'V-250613'
  tag rid: 'SV-250613r798838_rule'
  tag stig_id: 'GEN008680-ESXI5-000056'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54002r798837_fix'
  tag 'documentable'
  tag legacy: ['V-39428', 'SV-51286']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
