control 'SV-251231' do
  title 'Redis Enterprise DBMS must use NSA-approved cryptography to protect classified information in accordance with the data owners requirements.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

NSA-approved cryptography for classified networks is hardware based. This requirement addresses the compatibility of a DBMS with the encryption devices.

Redis Enterprise does not encrypt data at rest. Redis Enterprise encryption of data at rest is handled by the underlying Linux OS.'
  desc 'check', 'Determine if the organization requires encryption. If Redis is deployed in an unclassified environment, this is not applicable.

Determine if FIPS mode is enabled with the following command:
# sudo fipscheck

usage: fipscheck [-s <hmac-suffix>] <paths-to-files>
fips mode is on

If FIPS mode is "on", determine if the kernel command line is configured to use FIPS mode with the following command:
# sudo grep fips /boot/grub2/grub.cfg

/vmlinuz-3.8.0-0.40.el7.x86_64 root=/dev/mapper/rhel-root ro rd.md=0 rd.dm=0 rd.lvm.lv=rhel/swap crashkernel=auto rd.luks=0 vconsole.keymap=us rd.lvm.lv=rhel/root rhgb fips=1 quiet

If the kernel command line is configured to use FIPS mode, determine if the system is in FIPS mode with the following command:
# sudo cat /proc/sys/crypto/fips_enabled
1

If FIPS mode is not "on", the kernel command line does not have a FIPS entry, or the system has a value of "0" for "fips_enabled" in "/proc/sys/crypto", this is a finding.'
  desc 'fix', 'Configure the operating system to implement DoD-approved encryption by following the steps below:

To enable strict FIPS compliance, the fips=1 kernel option needs to be added to the kernel command line during system installation so key generation is done with FIPS-approved algorithms and continuous monitoring tests in place.

Enable FIPS mode with the following command:
# sudo fips-mode-setup --enable

Modify the kernel command line of the current kernel in the "grub.cfg" file by adding the following option to the GRUB_CMDLINE_LINUX key in the "/etc/default/grub" file and then rebuild the "grub.cfg" file:
fips=1

Changes to "/etc/default/grub" require rebuilding the "grub.cfg" file as follows:

On BIOS-based machines, use the following command:
# sudo grub2-mkconfig -o /boot/grub2/grub.cfg

On UEFI-based machines, use the following command:
# sudo grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg

If /boot or /boot/efi reside on separate partitions, the kernel parameter "boot=<partition of /boot or /boot/efi>" must be added to the kernel command line. Identify a partition by running the df /boot or df /boot/efi command:
# sudo df /boot

Filesystem 1K-blocks Used Available Use% Mounted on
/dev/sda1 495844 53780 416464 12% /boot

To ensure the "boot=" configuration option will work even if device naming changes occur between boots, identify the universally unique identifier (UUID) of the partition with the following command:
# sudo blkid /dev/sda1
/dev/sda1: UUID="05c000f1-a213-759e-c7a2-f11b7424c797" TYPE="ext4"

For the example above, append the following string to the kernel command line:
boot=UUID=05c000f1-a213-759e-c7a2-f11b7424c797

Reboot the system for the changes to take effect.'
  impact 0.7
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54666r804881_chk'
  tag severity: 'high'
  tag gid: 'V-251231'
  tag rid: 'SV-251231r855615_rule'
  tag stig_id: 'RD6X-00-009700'
  tag gtitle: 'SRG-APP-000416-DB-000380'
  tag fix_id: 'F-54620r804882_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
