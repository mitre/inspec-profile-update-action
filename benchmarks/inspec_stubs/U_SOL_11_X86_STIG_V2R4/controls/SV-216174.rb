control 'SV-216174' do
  title 'The operating system must use cryptographic mechanisms to protect and restrict access to information on portable digital media.'
  desc 'When data is written to portable digital media, such as thumb drives, floppy diskettes, compact disks, and magnetic tape, etc., there is risk of data loss. 

An organizational assessment of risk guides the selection of media and associated information contained on the media requiring restricted access. 

Organizations need to document in policy and procedures the media requiring restricted access, individuals authorized to access the media, and the specific measures taken to restrict access. Fewer protection measures are needed for media containing information determined by the organization to be in the public domain, to be publicly releasable, or to have limited or no adverse impact if accessed by other than authorized personnel. 

In these situations, it is assumed the physical access controls where the media resides provide adequate protection. The employment of cryptography is at the discretion of the information owner/steward. 

When the organization has determined the risk warrants it, data written to portable digital media must be encrypted.'
  desc 'check', 'This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Determine the logical node of all attached removable media:

# rmformat

This command lists all attached removable devices. Note the device logical node name. For example: /dev/rdsk/c8t0d0p0

Determine which zpool is mapped to the device:

# zpool status

Determine the file system names of the portable digital media:

# zfs list | grep [poolname]

Using the file system name, determine if the removal media is encrypted:

# zfs get encryption [filesystem] 

If "encryption off" is listed, this is a finding.'
  desc 'fix', 'The root role is required.

Format a removable device as a ZFS encrypted file system.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

The ZFS File System Management and ZFS Storage management profiles are required.

Insert the removable device:

# rmformat

This command lists all attached removable devices. Note the device logical node name. For example: /dev/rdsk/c8t0d0p0

Create an encrypted zpool on this device using a poolname of your choice:

# pfexec zpool create -O encryption=on [poolname] c8t0d0p0

Enter a passphrase and confirm the passphrase. Keep the passphrase secure.

Export the zpool before removing the media:

# pfexec export [poolname]

It will be necessary to enter the passphrase when inserting and importing the removable media zpool:
Insert the removable media
# pfexec import [poolname]

Only store data in the encrypted file system.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17412r372904_chk'
  tag severity: 'medium'
  tag gid: 'V-216174'
  tag rid: 'SV-216174r603268_rule'
  tag stig_id: 'SOL-11.1-060140'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17410r372905_fix'
  tag 'documentable'
  tag legacy: ['V-48157', 'SV-61029']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
