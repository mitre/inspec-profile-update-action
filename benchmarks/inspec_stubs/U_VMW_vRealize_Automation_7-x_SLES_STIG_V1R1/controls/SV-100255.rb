control 'SV-100255' do
  title 'The system must have USB disabled unless needed.'
  desc 'USB is a common computer peripheral interface. USB devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', 'If the system needs USB, this vulnerability is not applicable.

Check if the directory /proc/bus/usb exists. 

If the directory /proc/bus/usb exists, this is a finding.'
  desc 'fix', 'Edit the grub bootloader file /boot/grub/menu.lst by appending the "nousb" parameter to the kernel boot line.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89297r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89605'
  tag rid: 'SV-100255r1_rule'
  tag stig_id: 'VRAU-SL-000455'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-96347r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
