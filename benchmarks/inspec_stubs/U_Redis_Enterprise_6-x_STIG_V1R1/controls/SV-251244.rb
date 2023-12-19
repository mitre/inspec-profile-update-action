control 'SV-251244' do
  title 'Redis Enterprise DBMS must implement cryptographic mechanisms preventing the unauthorized disclosure of organization-defined information at rest on organization-defined information system components.'
  desc 'DBMSs handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to the DBMS or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.

Redis Enterprise does not inherently encrypt data at rest; however, this can be handled at the OS level.'
  desc 'check', 'Review the system documentation to determine whether the organization has defined the information at rest that is to be protected from disclosure, which must include, at a minimum, PII and classified information.

If the documentation indicates no information requires such protections, this is not a finding.

Verify the operating system implements encryption to protect the confidentiality and integrity of information at rest. 

If a disk or filesystem requires encryption, ask the system owner, DBA, and SA to demonstrate the use of filesystem and/or disk-level encryption. If this is required and is not found, this is a finding.

To check if full disk encryption is enabled, log in to RHEL as an Admin user and run the following commands:
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
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54679r809499_chk'
  tag severity: 'medium'
  tag gid: 'V-251244'
  tag rid: 'SV-251244r809500_rule'
  tag stig_id: 'RD6X-00-011000'
  tag gtitle: 'SRG-APP-000429-DB-000387'
  tag fix_id: 'F-54633r804921_fix'
  tag 'documentable'
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
