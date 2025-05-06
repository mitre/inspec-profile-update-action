control 'SV-216413' do
  title 'The operating system must protect the confidentiality and integrity of information at rest.'
  desc 'When data is written to digital media, such as hard drives, mobile computers, external/removable hard drives, personal digital assistants, flash/thumb drives, etc., there is risk of data loss and data compromise. 

An organizational assessment of risk guides the selection of media and associated information contained on the media requiring restricted access. Organizations need to document in policy and procedures the media requiring restricted access, individuals authorized to access the media, and the specific measures taken to restrict access. 

Fewer protection measures are needed for media containing information determined by the organization to be in the public domain, to be publicly releasable, or to have limited or no adverse impact if accessed by other than authorized personnel. In these situations, it is assumed the physical access controls where the media resides provide adequate protection. 

As part of a defense-in-depth strategy, the organization considers routinely encrypting information at rest on selected secondary storage devices. The employment of cryptography is at the discretion of the information owner/steward. The selection of the cryptographic mechanisms used is based upon maintaining the confidentiality and integrity of the information.'
  desc 'check', 'Determine if file system encryption is required by your organization. If not required, this item does not apply.

Determine if file system encryption is enabled for user data sets. This check does not apply to the root, var, share, swap or dump datasets.

# zfs list 

Using the file system name, determine if the file system is encrypted:

# zfs get encryption [filesystem] 

If "encryption off" is listed, this is a finding.'
  desc 'fix', "The ZFS file system management profile is required.

ZFS file system encryption may only be enabled on creation of the file system. If a file system must be encrypted and is not, its data should be archived, it must be removed and re-created.

First, stop running applications using the file systems, archive the data, unmount, and then remove the file system.

# umount [file system name]
# zfs destroy [file system name]

When creating ZFS file systems, ensure that they are created as encrypted file systems.

# pfexec zfs create -o encryption=on [file system name]
Enter passphrase for '[file system name]': xxxxxxx
Enter again: xxxxxxx

Store the passphrase in a safe location. The passphrase will be required to mount the file systems upon system reboot. If automated mounting is required, the passphrase must be stored in a file."
  impact 0.3
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17649r371327_chk'
  tag severity: 'low'
  tag gid: 'V-216413'
  tag rid: 'SV-216413r603267_rule'
  tag stig_id: 'SOL-11.1-060160'
  tag gtitle: 'SRG-OS-000185'
  tag fix_id: 'F-17647r371328_fix'
  tag 'documentable'
  tag legacy: ['SV-61025', 'V-48153']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
