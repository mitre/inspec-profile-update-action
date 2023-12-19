control 'SV-218028' do
  title 'The operating system must protect the confidentiality and integrity of data at rest.'
  desc "The risk of a system's physical compromise, particularly mobile systems such as laptops, places its data at risk of compromise. Encrypting this data mitigates the risk of its loss if the system is lost."
  desc 'check', 'Determine if encryption must be used to protect data on the system. 
If encryption must be used and is not employed, this is a finding.'
  desc 'fix', 'Red Hat Enterprise Linux 6 natively supports partition encryption through the Linux Unified Key Setup-on-disk-format (LUKS) technology. The easiest way to encrypt a partition is during installation time. 

For manual installations, select the "Encrypt" checkbox during partition creation to encrypt the partition. When this option is selected the system will prompt for a passphrase to use in decrypting the partition. The passphrase will subsequently need to be entered manually every time the system boots. 

For automated/unattended installations, it is possible to use Kickstart by adding the "--encrypted" and "--passphrase=" options to the definition of each partition to be encrypted. For example, the following line would encrypt the root partition: 

part / --fstype=ext3 --size=100 --onpart=hda1 --encrypted --passphrase=[PASSPHRASE]

Any [PASSPHRASE] is stored in the Kickstart in plaintext, and the Kickstart must then be protected accordingly. Omitting the "--passphrase=" option from the partition definition will cause the installer to pause and interactively ask for the passphrase during installation. 

Detailed information on encrypting partitions using LUKS can be found on the Red Hat Documentation web site:

https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-LUKS_Disk_Encryption.html'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19509r377099_chk'
  tag severity: 'low'
  tag gid: 'V-218028'
  tag rid: 'SV-218028r603264_rule'
  tag stig_id: 'RHEL-06-000276'
  tag gtitle: 'SRG-OS-000185'
  tag fix_id: 'F-19507r377100_fix'
  tag 'documentable'
  tag legacy: ['V-38661', 'SV-50462']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
