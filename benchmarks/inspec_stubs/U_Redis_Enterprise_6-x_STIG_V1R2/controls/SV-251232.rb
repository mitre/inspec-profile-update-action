control 'SV-251232' do
  title 'Redis Enterprise DBMS must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to provision digital signatures.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

For detailed information, refer to NIST FIPS Publication 140-2 or Publication 140-3, Security Requirements for Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', %q(The DBMS relies on the underlying operating system's cryptographic modules to provision digital signatures. Verify the operating system implements DoD-approved encryption to protect the confidentiality of remote access sessions.

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

If FIPS mode is not "on", the kernel command line does not have a FIPS entry, or the system has a value of "0" for "fips_enabled" in "/proc/sys/crypto", this is a finding.)
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
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54667r804884_chk'
  tag severity: 'medium'
  tag gid: 'V-251232'
  tag rid: 'SV-251232r863367_rule'
  tag stig_id: 'RD6X-00-009800'
  tag gtitle: 'SRG-APP-000514-DB-000381'
  tag fix_id: 'F-54621r804885_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
