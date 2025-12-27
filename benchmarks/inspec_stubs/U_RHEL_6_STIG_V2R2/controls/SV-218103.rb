control 'SV-218103' do
  title 'Auditing must be enabled at boot by setting a kernel parameter.'
  desc 'Each process on the system carries an "auditable" flag which indicates whether its activities can be audited. Although "auditd" takes care of enabling this for all processes which launch after it does, adding the kernel argument ensures it is set for every process during boot.'
  desc 'check', 'Inspect the kernel boot arguments (which follow the word "kernel") in "/boot/grub/grub.conf". If they include "audit=1", then auditing is enabled at boot time.

If auditing is not enabled at boot time, this is a finding.

If the system uses UEFI inspect the kernel boot arguments (which follow the word "kernel") in “/boot/efi/EFI/redhat/grub.conf”. If they include "audit=1", then auditing is enabled at boot time.'
  desc 'fix', 'To ensure all processes can be audited, even those which start prior to the audit daemon, add the argument "audit=1" to the kernel line in "/boot/grub/grub.conf" or “/boot/efi/EFI/redhat/grub.conf”, in the manner below:

kernel /vmlinuz-version ro vga=ext root=/dev/VolGroup00/LogVol00 rhgb quiet audit=1

UEFI systems may prepend "/boot" to the "/vmlinuz-version" argument.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19584r462421_chk'
  tag severity: 'low'
  tag gid: 'V-218103'
  tag rid: 'SV-218103r603264_rule'
  tag stig_id: 'RHEL-06-000525'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-19582r462422_fix'
  tag 'documentable'
  tag legacy: ['SV-50238', 'V-38438']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
