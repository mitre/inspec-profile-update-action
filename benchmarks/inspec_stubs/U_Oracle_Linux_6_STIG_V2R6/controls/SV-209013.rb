control 'SV-209013' do
  title 'The operating system must protect the confidentiality and integrity of data at rest.'
  desc "The risk of a system's physical compromise, particularly mobile systems such as laptops, places its data at risk of compromise. Encrypting this data mitigates the risk of its loss if the system is lost."
  desc 'check', 'Determine if encryption must be used to protect data on the system. 
If encryption must be used and is not employed, this is a finding.'
  desc 'fix', 'The operating system natively supports partition encryption through the Linux Unified Key Setup (LUKS) on-disk-format technology.  The easiest way to encrypt a partition is during installation time.

For manual installations, select the "Encrypt" checkbox during partition creation to encrypt the partition. When this option is selected, the system will prompt for a passphrase to use in decrypting the partition. The passphrase will subsequently need to be entered manually every time the system boots. 

For automated/unattended installations, it is possible to use Kickstart by adding the "--encrypted" and "--passphrase=" options to the definition of each partition to be encrypted. For example, the following line would encrypt the root partition: 

part / --fstype=ext3 --size=100 --onpart=hda1 --encrypted --passphrase=[PASSPHRASE]

Any [PASSPHRASE] is stored in the Kickstart in plaintext, and the Kickstart must then be protected accordingly. Omitting the "--passphrase=" option from the partition definition will cause the installer to pause and interactively ask for the passphrase during installation. 

Detailed information on encrypting partitions using LUKS can be found in the Oracle Linux documentation at:

http://docs.oracle.com/cd/E37670_01/E36387/html/index.html

Additional information is available from: 

http://linux.oracle.com/documentation/OL6/Red_Hat_Enterprise_Linux-6-Security_Guide-en-US.pdf'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9266r357824_chk'
  tag severity: 'low'
  tag gid: 'V-209013'
  tag rid: 'SV-209013r793734_rule'
  tag stig_id: 'OL6-00-000276'
  tag gtitle: 'SRG-OS-000185'
  tag fix_id: 'F-9266r357825_fix'
  tag 'documentable'
  tag legacy: ['V-50859', 'SV-65065']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
