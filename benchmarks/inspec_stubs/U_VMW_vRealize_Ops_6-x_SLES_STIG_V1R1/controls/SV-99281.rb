control 'SV-99281' do
  title 'The SLES for vRealize must initiate session audits at system start-up.'
  desc 'If auditing is enabled late in the start-up process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Check for the "audit=1" kernel parameter.

# grep "audit=1" /proc/cmdline

If no results are returned, this is a finding.'
  desc 'fix', 'Edit the grub bootloader file "/boot/grub/menu.lst" by appending the "audit=1" parameter to the kernel boot line.

Reboot the system for the change to take effect.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88323r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88631'
  tag rid: 'SV-99281r1_rule'
  tag stig_id: 'VROM-SL-000870'
  tag gtitle: 'SRG-OS-000254-GPOS-00095'
  tag fix_id: 'F-95373r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
