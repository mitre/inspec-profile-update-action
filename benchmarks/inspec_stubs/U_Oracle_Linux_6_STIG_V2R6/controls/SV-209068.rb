control 'SV-209068' do
  title 'Auditing must be enabled at boot by setting a kernel parameter.'
  desc 'Each process on the system carries an "auditable" flag which indicates whether its activities can be audited. Although "auditd" takes care of enabling this for all processes which launch after it does, adding the kernel argument ensures it is set for every process during boot.'
  desc 'check', 'Inspect the kernel boot arguments (which follow the word "kernel") in "/etc/grub.conf". If they include "audit=1", then auditing is enabled at boot time. 
If auditing is not enabled at boot time, this is a finding.'
  desc 'fix', 'To ensure all processes can be audited, even those which start prior to the audit daemon, add the argument "audit=1" to the kernel line in "/boot/grub/grub.conf", in the manner below:

kernel /vmlinuz-version ro vga=ext root=/dev/VolGroup00/LogVol00 rhgb quiet audit=1

UEFI systems may prepend "/boot" to the "/vmlinuz-version" argument.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9321r357989_chk'
  tag severity: 'low'
  tag gid: 'V-209068'
  tag rid: 'SV-209068r793789_rule'
  tag stig_id: 'OL6-00-000525'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-9321r357990_fix'
  tag 'documentable'
  tag legacy: ['SV-64723', 'V-50517']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
