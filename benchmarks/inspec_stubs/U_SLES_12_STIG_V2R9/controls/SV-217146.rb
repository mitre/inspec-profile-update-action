control 'SV-217146' do
  title 'All SUSE operating system persistent disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.'
  desc 'SUSE operating systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

'
  desc 'check', 'Verify the SUSE operating system prevents unauthorized disclosure or modification of all information requiring at rest protection by using disk encryption. 

Determine the partition layout for the system with the following command:

# sudo fdisk -l

Device     Boot    Start       End  Sectors  Size Id Type
/dev/sda1           2048   4208639  4206592    2G 82 Linux swap / Solaris
/dev/sda2  *     4208640  53479423 49270784 23.5G 83 Linux
/dev/sda3       53479424 125829119 72349696 34.5G 83 Linux

Verify the system partitions are all encrypted with the following command: 

# sudo more /etc/crypttab

luks       UUID=114167a-2a94-6cda-f1e7-15ad146c258b
swap       /dev/sda1       /dev/urandom       swap
truecrypt  /dev/sda2       /etc/container_password  tcrypt
truecrypt  /dev/sda3       /etc/container_password  tcrypt

Every persistent disk partition present on the system must have an entry in the file. 

If any partitions other than pseudo file systems (such as /proc or /sys) are not listed or "/etc/crypttab" does not exist, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to prevent unauthorized modification of all information at rest by using disk encryption. 

Encrypting a partition in an already-installed system is more difficult because of the need to resize and change existing partitions. To encrypt an entire partition, dedicate a partition for encryption in the partition layout. The standard partitioning proposal as suggested by YaST (installation and configuration tool for Linux) does not include an encrypted partition by default. Add it manually in the partitioning dialog.

Refer to the document "SUSE 12 Security Guide", Section 11.1, for a detailed disk encryption guide:

https://www.suse.com/documentation/sles-12/book_security/data/sec_security_cryptofs_y2.html#sec_security_cryptofs_y2_part_run'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18374r369594_chk'
  tag severity: 'medium'
  tag gid: 'V-217146'
  tag rid: 'SV-217146r854086_rule'
  tag stig_id: 'SLES-12-010450'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-18372r369595_fix'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag 'documentable'
  tag legacy: ['V-77147', 'SV-91843']
  tag cci: ['CCI-001199', 'CCI-002475']
  tag nist: ['SC-28', 'SC-28 (1)']
end
