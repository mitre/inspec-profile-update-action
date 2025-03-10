control 'SV-253703' do
  title 'MariaDB must use NIST FIPS 140-2 validated cryptographic modules for cryptographic operations.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data. Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality, or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the DBMS.

Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.  

The security functions validated as part of FIPS 140-2 for cryptographic modules are described in FIPS 140-2 Annex A.

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.'
  desc 'check', "As the system administrator, run the following at the Linux commands:
 
# openssl version
OpenSSL 1.0.2k-fips  26 Jan 2017

If fips is not included in the openssl version, this is a finding. 

# sysctl crypto.fips_enabled
crypto.fips_enabled = 1
 
If crypto.fips_enabled = 0, this is a finding. 
 
MariaDB> SHOW GLOBAL VARIABLES LIKE '%have_openssl';

If the value of have_openssl is not YES, this is a finding.

MariaDB> SHOW GLOBAL VARIABLES LIKE '%version_ssl_library%';

If the value of version_ssl_library does not contain fips, this is a finding.

Examine the application's code to verify it does not make calls using libmysqlclient.  

If code uses libmysqlclient, this is a finding."
  desc 'fix', 'If crypto.fips_enabled = 0, for Red Hat Linux, configure the operating system to implement DoD-approved encryption by following the steps below:

To enable strict FIPS compliance, the fips=1 kernel option must be added to the kernel command line during system installation so key generation is done with FIPS-approved algorithms and continuous monitoring tests in place.

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

Reboot the system for the changes to take effect.

More information can be found here:
RedHat: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-federal_standards_and_regulations
Ubuntu: https://security-certs.docs.ubuntu.com/en/fips'
  impact 0.7
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57155r841632_chk'
  tag severity: 'high'
  tag gid: 'V-253703'
  tag rid: 'SV-253703r841634_rule'
  tag stig_id: 'MADB-10-004400'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-57106r841633_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
