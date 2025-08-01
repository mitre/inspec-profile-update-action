control 'SV-219149' do
  title 'The Ubuntu operating system must initiate session audits at system startup.'
  desc 'If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Verify the Ubuntu operating system enables auditing at system startup. 

Check that the auditing is enabled in grub with the following command:

grep "^\\s*linux" /boot/grub/grub.cfg

linux /vmlinuz-4.15.0-55-generic root=/dev/mapper/ubuntu--vg-root ro quiet splash $vt_handoff audit=1
linux /vmlinuz-4.15.0-55-generic root=/dev/mapper/ubuntu--vg-root ro recovery nomodeset audit=1

If any linux lines do not contain "audit=1", this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to produce audit records at system startup. 

Edit /etc/default/grub file and add "audit=1" to the GRUB_CMDLINE_LINUX option.

To update the grub config file run,

sudo update-grub'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20874r304775_chk'
  tag severity: 'medium'
  tag gid: 'V-219149'
  tag rid: 'SV-219149r610963_rule'
  tag stig_id: 'UBTU-18-010002'
  tag gtitle: 'SRG-OS-000254-GPOS-00095'
  tag fix_id: 'F-20873r304776_fix'
  tag 'documentable'
  tag legacy: ['V-100523', 'SV-109627']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
