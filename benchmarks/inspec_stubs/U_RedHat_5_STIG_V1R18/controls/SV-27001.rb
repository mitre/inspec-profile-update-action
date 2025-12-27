control 'SV-27001' do
  title 'Auditing must be enabled at boot by setting a kernel parameter.'
  desc 'If auditing is enabled late in the boot process, the actions of startup scripts may not be audited.  Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', "Check for the audit=1 kernel parameter.
# grep 'audit=1' /proc/cmdline
If no results are returned, this is a finding."
  desc 'fix', 'Edit the grub bootloader file /boot/grub/grub.conf or /boot/grub/menu.lst by appending the "audit=1" parameter to the kernel boot line.
Reboot the system for the change to take effect.'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36032r1_chk'
  tag severity: 'low'
  tag gid: 'V-22598'
  tag rid: 'SV-27001r1_rule'
  tag stig_id: 'GEN000000-LNX00720'
  tag gtitle: 'GEN000000-LNX00720'
  tag fix_id: 'F-31278r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
