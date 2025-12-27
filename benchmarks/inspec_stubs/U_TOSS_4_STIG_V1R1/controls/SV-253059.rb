control 'SV-253059' do
  title 'TOSS must implement NIST FIPS-validated cryptography for the following: to provision digital signatures; to generate cryptographic hashes; and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

TOSS utilizes GRUB 2 as the default bootloader. Note that GRUB 2 command-line parameters are defined in the "kernelopts" variable of the /boot/grub2/grubenv file for all kernel boot entries. The command "fips-mode-setup" modifies the "kernelopts" variable, which in turn updates all kernel boot entries. 

The fips=1 kernel option needs to be added to the kernel command line during system installation so that key generation is done with FIPS-approved algorithms and continuous monitoring tests in place. Users must also ensure the system has plenty of entropy during the installation process by moving the mouse around, or if no mouse is available, ensuring that many keystrokes are typed. The recommended amount of keystrokes is 256 and more. Less than 256 keystrokes may generate a non-unique key.

'
  desc 'check', 'Verify TOSS implements DoD-approved encryption to protect the confidentiality of remote access sessions.

Check to see if FIPS mode is enabled with the following command:

$ fips-mode-setup --check

FIPS mode is enabled

If FIPS mode is "enabled", check to see if the kernel boot parameter is configured for FIPS mode with the following command:

$ sudo grub2-editenv list | grep fips

kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

If the kernel boot parameter is configured to use FIPS mode, check to see if the system is in FIPS mode with the following command:

$ sudo cat /proc/sys/crypto/fips_enabled

1

If FIPS mode is not "on", the kernel boot parameter is not configured for FIPS mode, or the system does not have a value of "1" for "fips_enabled" in "/proc/sys/crypto", this is a finding.

If the hardware configuration of the operating system does not allow for enabling FIPS mode, and has been documented with the Information System Security Officer (ISSO), this requirement is Not Applicable.'
  desc 'fix', 'Configure the operating system to implement DoD-approved encryption by following the steps below:

To enable strict FIPS compliance, the fips=1 kernel option needs to be added to the kernel boot parameters during system installation so key generation is done with FIPS-approved algorithms and continuous monitoring tests in place.

Enable FIPS mode after installation (not strict FIPS compliant) with the following command:

$ sudo fips-mode-setup --enable

Reboot the system for the changes to take effect.'
  impact 0.7
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56512r824847_chk'
  tag severity: 'high'
  tag gid: 'V-253059'
  tag rid: 'SV-253059r825086_rule'
  tag stig_id: 'TOSS-04-040040'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-56462r824848_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000396-GPOS-00176', 'SRG-OS-000478-GPOS-00223']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'SC-13 b']
end
