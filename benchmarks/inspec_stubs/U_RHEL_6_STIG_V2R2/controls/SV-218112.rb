control 'SV-218112' do
  title 'The Red Hat Enterprise Linux operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government to ensure the algorithms have been tested and validated.'
  desc 'check', 'Verify the operating system implements DoD-approved encryption to protect the confidentiality of remote access sessions.

Check to see if the "dracut-fips" package is installed with the following command:

# yum list installed dracut-fips

dracut-fips-004-411.el6.noarch.rpm

If a "dracut-fips" package is installed, use the following command to verify  the kernel command line is configured to use FIPS mode:

Note: GRUB reads its configuration from the "/boot/grub/grub.conf" file on traditional BIOS-based machines and from the "/boot/efi/EFI/redhat/grub.conf" file on UEFI machines.

# grep fips /boot/grub/grub.conf

kernel /vmlinuz-2.6.32-573.el6.x86_64 ro root=/dev/mapper/VolGroup-lv_root rd_NO_LUKS LANG=en_US.UTF-8 rd_NO_MD rd_LVM_LV=VolGroup/lv_swap SYSFONT=latarcyrheb-sun16 crashkernel=auto rd_LVM_LV=VolGroup/lv_root  KEYBOARDTYPE=pc KEYTABLE=us rd_NO_DM rhgb quiet fips=1 boot=/dev/sda1

If the kernel command line is configured to use FIPS mode, use the following command to verify the system is in FIPS mode::

# cat /proc/sys/crypto/fips_enabled 
1

If a "dracut-fips" package is not installed, the kernel command line does not have a fips entry, or the system has a value of "0" for "fips_enabled" in "/proc/sys/crypto", this is a finding.'
  desc 'fix', 'Configure the operating system to implement DoD-approved encryption by installing the dracut-fips package.

To enable strict FIPS compliance, the fips=1 kernel option must be added to the kernel command line during system installation to ensure key generation is completed with FIPS-approved algorithms and continuous monitoring tests in place.

Configure the operating system to implement DoD-approved encryption by following the steps below: 

The fips=1 kernel option must be added to the kernel command line during system installation to ensure key generation is completed with FIPS-approved algorithms and continuous monitoring tests in place. Users must ensure the system has plenty of entropy during the installation process by moving the mouse around, or if no mouse is available, ensuring many keystrokes are typed. The recommended number of keystrokes is 256 or more. Less than 256 keystrokes may generate a non-unique key.

Install the dracut-fips package with the following command:

# yum install dracut-fips

Undo existing prelinking, if necessary, on all system files using the following command: 

# prelink -au

Recreate the "initramfs" file with the following command:

Note: This command will overwrite the existing "initramfs" file.

# dracut -f

Add the following option to the "grub.conf" file to modify the kernel command line of the current kernel in the "grub.conf" file:

fips=1

If /boot or /boot/efi reside on separate partitions, the kernel parameter boot=<partition of /boot or /boot/efi> must be added to the kernel command line. Identify partitions by running the df /boot or df /boot/efi command:

# df /boot

Filesystem 1K-blocks Used Available Use% Mounted on
/dev/sda1 495844 53780 416464 12% /boot

To ensure the "boot=" configuration option will work if device naming changes occur between boots, identify the universally unique identifier (UUID) of the partition with the following command:

# blkid /dev/sda1

/dev/sda1: UUID="05c000f1-a213-759e-c7a2-f11b7424c797" TYPE="ext4"

For the example above, append the following string to the kernel command line:

boot=UUID=05c000f1-a213-759e-c7a2-f11b7424c797

Reboot the system for the changes to take effect.'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19593r462510_chk'
  tag severity: 'high'
  tag gid: 'V-218112'
  tag rid: 'SV-218112r603264_rule'
  tag stig_id: 'RHEL-06-000534'
  tag gtitle: 'SRG-OS-000033'
  tag fix_id: 'F-19591r462511_fix'
  tag 'documentable'
  tag legacy: ['SV-106367', 'V-97229']
  tag cci: ['CCI-000068', 'CCI-002450', 'CCI-002476', 'CCI-001199']
  tag nist: ['AC-17 (2)', 'SC-13 b', 'SC-28 (1)', 'SC-28']
end
