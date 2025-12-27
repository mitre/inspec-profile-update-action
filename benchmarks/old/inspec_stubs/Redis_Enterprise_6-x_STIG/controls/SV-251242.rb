control 'SV-251242' do
  title 'Redis Enterprise DBMS must protect the confidentiality and integrity of all information at rest.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use. 

User data generated, as well as application-specific configuration data, needs to be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate. 

If the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification.

Redis Enterprise does not inherently encrypt data at rest and is designed to have the OS handle encryption for data at rest.'
  desc 'check', 'If the application owner and Authorizing Official have determined that encryption of data at rest is NOT required, this is not a finding.

Verify the operating system implements encryption to protect the confidentiality and integrity of information at rest.

If a disk or filesystem requires encryption, ask the system owner, DBA, and SA to demonstrate the use of filesystem and/or disk-level encryption. If this is required and is not found, this is a finding.

To check if full disk encryption is enabled, log in to RHEL as an admin user and run the following commands:
# lsblk

Identify the partition that Redis Enterprise is located on.
# blkid /dev/[name of partition]

If the output shows TYPE="crypto_LUKS" then the partition is encrypted.

If encryption must be used and is not employed, this is a finding.'
  desc 'fix', 'Red Hat Enterprise Linux natively supports partition encryption through the Linux Unified Key Setup-on-disk-format (LUKS) technology. The easiest way to encrypt a partition is during installation time.

For manual installations, select the "Encrypt" checkbox during partition creation to encrypt the partition. When this option is selected the system will prompt for a passphrase to use in decrypting the partition. The passphrase will subsequently need to be entered manually every time the system boots.

For automated/unattended installations, it is possible to use Kickstart by adding the "--encrypted" and "--passphrase=" options to the definition of each partition to be encrypted. For example, the following line would encrypt the root partition:
part / --fstype=ext3 --size=100 --onpart=hda1 --encrypted --passphrase=[PASSPHRASE]

Any [PASSPHRASE] is stored in the Kickstart in plaintext, and the Kickstart must then be protected accordingly. Omitting the "--passphrase=" option from the partition definition will cause the installer to pause and interactively ask for the passphrase during installation.

Detailed information on encrypting partitions using LUKS can be found on the Red Hat Documentation website: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-encryption'
  impact 0.7
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54677r804914_chk'
  tag severity: 'high'
  tag gid: 'V-251242'
  tag rid: 'SV-251242r804916_rule'
  tag stig_id: 'RD6X-00-010800'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-54631r804915_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
