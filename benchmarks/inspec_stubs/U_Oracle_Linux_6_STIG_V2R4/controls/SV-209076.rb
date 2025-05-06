control 'SV-209076' do
  title 'The Oracle Linux 6 operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

'
  desc 'check', 'Verify the operating system implements DoD-approved encryption to protect the confidentiality of remote access sessions.

Check to see if the "dracut-fips" package is installed with the following command:

# yum list installed dracut-fips

dracut-fips-004-411.el6.noarch.rpm

If a "dracut-fips" package is installed, check to see if the kernel command line is configured to use FIPS mode with the following command:

# grep fips /boot/grub/grub.conf

kernel /boot/vmlinuz-4.1.12-124.18.5.el6uek.x86_64 ro root=/dev/mapper/VolGroup-lv_root rd_NO_LUKS KEYBOARDTYPE=pc KEYTABLE=uk LANG=en_US.UTF-8 rd_NO_MD rd_LVM_LV=VolGroup/lv_swap SYSFONT=latarcyrheb-sun16  rd_LVM_LV=VolGroup/lv_root rd_NO_DM rhgb quiet fips=1 boot=/dev/sda1

If the kernel command line is configured to use FIPS mode, check to see if the system is in FIPS mode with the following command:

# cat /proc/sys/crypto/fips_enabled 
1

If a "dracut-fips" package is not installed, the kernel command line does not have a fips entry, or the system has a value of "0" for "fips_enabled" in "/proc/sys/crypto", this is a finding.'
  desc 'fix', 'Configure the operating system to implement DoD-approved encryption by installing the dracut-fips package.

To enable strict FIPS compliance, the fips=1 kernel option needs to be added to the kernel command line during system installation so key generation is done with FIPS-approved algorithms and continuous monitoring tests in place.

Configure the operating system to implement DoD-approved encryption by following the steps below: 

The fips=1 kernel option needs to be added to the kernel command line during system installation so that key generation is done with FIPS-approved algorithms and continuous monitoring tests in place. Users should also ensure that the system has plenty of entropy during the installation process by moving the mouse around, or if no mouse is available, ensuring that many keystrokes are typed. The recommended amount of keystrokes is 256 and more. Less than 256 keystrokes may generate a non-unique key.

Install the dracut-fips package with the following command:

# yum install dracut-fips

Existing prelinking, if any, should be undone on all system files using the following command: 

# prelink -u -a

Recreate the "initramfs" file with the following command:

Note: This command will overwrite the existing "initramfs" file.

# dracut -f

Modify the kernel command line of the current kernel in the "grub.conf" file by adding the following option to the "grub.conf" file:

fips=1

If /boot or /boot/efi reside on separate partitions, the kernel parameter boot=<partition of /boot or /boot/efi> must be added to the kernel command line. You can identify a partition by running the df /boot or df /boot/efi command:

# df /boot

Filesystem 1K-blocks Used Available Use% Mounted on
/dev/sda1 495844 53780 416464 12% /boot

To ensure the "boot=" configuration option will work even if device naming changes occur between boots, identify the universally unique identifier (UUID) of the partition with the following command:

# blkid /dev/sda1

/dev/sda1: UUID="05c000f1-a213-759e-c7a2-f11b7424c797" TYPE="ext4"

For the example above, append the following string to the kernel command line:

boot=UUID=05c000f1-a213-759e-c7a2-f11b7424c797

Reboot the system for the changes to take effect.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9329r462525_chk'
  tag severity: 'high'
  tag gid: 'V-209076'
  tag rid: 'SV-209076r603263_rule'
  tag stig_id: 'OL6-00-000534'
  tag gtitle: 'SRG-OS-NA-000033'
  tag fix_id: 'F-9329r462526_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000185-GPOS-00079', 'SRG-OS-000396-GPOS-00176', 'SRG-OS-000405-GPOS-00184', 'SRG-OS-000478-GPOS-00223']
  tag 'documentable'
  tag legacy: ['V-97233', 'SV-106371']
  tag cci: ['CCI-000068', 'CCI-001199', 'CCI-002450', 'CCI-002476']
  tag nist: ['AC-17 (2)', 'SC-28', 'SC-13 b', 'SC-28 (1)']
end
