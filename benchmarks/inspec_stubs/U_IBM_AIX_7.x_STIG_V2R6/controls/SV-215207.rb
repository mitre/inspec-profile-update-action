control 'SV-215207' do
  title 'AIX must protect the confidentiality and integrity of all information at rest.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive, when used for backups) within an operating system.

This requirement addresses protection of user-generated data, as well as operating system-specific configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information.'
  desc 'check', 'If the organization does not require to encrypt the data at rest this is Not Applicable.

Check if the "clic.rte" fileset is installed:
# lslpp -l |grep clic

The above command should yield the following output:
  clic.rte.kernext          4.10.0.1  COMMITTED  CryptoLite for C Kernel
  clic.rte.lib                     4.10.0.1  COMMITTED  CryptoLite for C Library
  clic.rte.kernext          4.10.0.1  COMMITTED  CryptoLite for C Kernel

If the "clic.rte" fileset is not installed, this is a finding.

To check if a JFS2 file system (mounted as /fs2_mnt) is EFS-enabled, use the following command:

# lsfs -q /fs2_mnt

Name            Nodename   Mount Pt               VFS   Size    Options    Auto Accounting
/dev/fslv00     --         /fs2_mnt                   jfs2  262144  --         no   no 
  (lv size: 262144, fs size: 262144, block size: 4096, sparse files: yes, inline log: no, inline log size: 0, EAformat: v2, Quota: no, DMAPI: no, VIX: yes, EFS: no, ISNAPSHOT: no, MAXEXT: 0, MountGuard: no)

If the above command shows "EFS: no", this is a finding.'
  desc 'fix', 'Install "clic.rte" fileset if it is not installed using command:
# installp -aXYqg -d /dev/cd0 clic.rte

Run the follow command to initialize and enable EFS on the system:
# efsenable -a

To create a new EFS-enabled JFS2 file system and mount the file system, using the following commands:
# crfs -v jfs2 -g rootvg -m /fs2 -a size=100M -a efs=yes
# mount /fs2

To enable EFS on a JFS2 file system (like, /fs3), run the following command:
chfs -a efs=yes /fs3'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16405r294072_chk'
  tag severity: 'medium'
  tag gid: 'V-215207'
  tag rid: 'SV-215207r508663_rule'
  tag stig_id: 'AIX7-00-001048'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-16403r294073_fix'
  tag 'documentable'
  tag legacy: ['V-91449', 'SV-101547']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
