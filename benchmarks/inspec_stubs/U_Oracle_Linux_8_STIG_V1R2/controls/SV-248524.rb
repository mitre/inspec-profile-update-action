control 'SV-248524' do
  title 'OL 8 must implement NIST FIPS-validated cryptography for the following: To provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated. 
 
OL 8 uses GRUB 2 as the default bootloader. Note that GRUB 2 command-line parameters are defined in the "kernelopts" variable of the "/boot/grub2/grubenv" file for all kernel boot entries. The command "fips-mode-setup" modifies the "kernelopts" variable, which in turn updates all kernel boot entries.

The fips=1 kernel option needs to be added to the kernel command line during system installation so that key generation is done with FIPS-approved algorithms and continuous monitoring tests in place. Users must also ensure the system has plenty of entropy during the installation process by moving the mouse around, or if no mouse is available, ensuring that many keystrokes are typed. The recommended amount of keystrokes is 256 and more. Less than 256 keystrokes may generate a non-unique key.

'
  desc 'check', 'Verify the operating system implements DoD-approved encryption to protect the confidentiality of remote access sessions.

Check to see if FIPS mode is enabled with the following command:

$ fips-mode-setup --check

FIPS mode is enabled

If FIPS mode is "enabled", check to see if the kernel boot parameter is configured for FIPS mode with the following command:

$ sudo grub2-editenv list | grep fips

kernelopts=root=/dev/mapper/ol-root ro resume=/dev/mapper/ol-swap rd.lvm.lv=ol/root rd.lvm.lv=ol/swap rhgb quiet fips=1 boot=UUID=25856928-386b-4205-9a0e-a2953ae2712d audit=1 audit_backlog_limit=8192 pti=on random.trust_cpu=on slub_debug=P page_poison=1

If the kernel boot parameter is configured to use FIPS mode, check to see if the system is in FIPS mode with the following command:

$ sudo cat /proc/sys/crypto/fips_enabled

1

If FIPS mode is not "enabled", the kernel boot parameter is not configured for FIPS mode, or the system does not have a value of "1" for "fips_enabled" in "/proc/sys/crypto", this is a finding.'
  desc 'fix', 'Configure the operating system to implement DoD-approved encryption by following the steps below:

To enable strict FIPS compliance, the fips=1 kernel option needs to be added to the kernel boot parameters during system installation so key generation is done with FIPS-approved algorithms and continuous monitoring tests in place.

Enable FIPS mode after installation (not strict FIPS compliant) with the following command:

$ sudo fips-mode-setup --enable

Reboot the system for the changes to take effect.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51958r818786_chk'
  tag severity: 'high'
  tag gid: 'V-248524'
  tag rid: 'SV-248524r818787_rule'
  tag stig_id: 'OL08-00-010020'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-51912r779137_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000423-GPOS-00187']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000877', 'CCI-001453', 'CCI-002418', 'CCI-002890', 'CCI-003123']
  tag nist: ['AC-17 (2)', 'MA-4 c', 'AC-17 (2)', 'SC-8', 'MA-4 (6)', 'MA-4 (6)']
end
