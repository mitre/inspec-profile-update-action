control 'SV-218715' do
  title 'The system must have USB Mass Storage disabled unless needed.'
  desc 'USB is a common computer peripheral interface. USB devices may include storage devices with the potential to install malicious software on a system or exfiltrate data'
  desc 'check', "If the system needs USB storage, this vulnerability is not applicable.
Check if usb-storage is prevented from loading.
# grep 'install usb-storage /bin/true' /etc/modprobe.conf /etc/modprobe.d/*
If no results are returned, this is a finding."
  desc 'fix', "Prevent the usb-storage module from loading.
# echo 'install usb-storage /bin/true' >> /etc/modprobe.conf"
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20190r556562_chk'
  tag severity: 'low'
  tag gid: 'V-218715'
  tag rid: 'SV-218715r603259_rule'
  tag stig_id: 'GEN008480'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20188r556563_fix'
  tag 'documentable'
  tag legacy: ['V-22579', 'SV-63179']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
