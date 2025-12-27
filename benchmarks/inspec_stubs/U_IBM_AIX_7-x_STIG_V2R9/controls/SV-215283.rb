control 'SV-215283' do
  title 'AIX must encrypt user data at rest using AIX Encrypted File System (EFS) if it is required.'
  desc 'The AIX Encrypted File System (EFS) is a J2 filesystem-level encryption through individual key stores. This allows for file encryption in order to protect confidential data from attackers with physical access to the computer. User authentication and access control lists can protect files from unauthorized access (even from root user) while the operating system is running. 

Operating systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

'
  desc 'check', 'If the organization does not require to encrypt the data at rest, this is Not Applicable.

Check if "clic.rte" fileset is installed:
# lslpp -l |grep clic

The above command should yield the following output:
  clic.rte.kernext          4.10.0.1  COMMITTED  CryptoLite for C Kernel
  clic.rte.lib                    4.10.0.1  COMMITTED  CryptoLite for C Library
  clic.rte.kernext          4.10.0.1  COMMITTED  CryptoLite for C Kernel

If the "clic.rte.lib", or the "clic.rte.kernext", fileset is not installed, this is a finding.

To check if a JFS2 file system (mounted as /fs2_mnt) is EFS-enabled, use the following command:
# lsfs -q /fs2_mnt

Name            Nodename   Mount Pt               VFS   Size    Options    Auto Accounting
/dev/fslv00     --         /fs2_mnt                   jfs2  262144  --         no   no 
  (lv size: 262144, fs size: 262144, block size: 4096, sparse files: yes, inline log: no, inline log size: 0, EAformat: v2, Quota: no, DMAPI: no, VIX: yes, EFS: no, ISNAPSHOT: no, MAXEXT: 0, MountGuard: no)

If the above command shows "EFS: no", this is a finding.'
  desc 'fix', 'Install "clic.rte" filesets from AIX DVD Volume 1 using the following commands (assuming that the DVD device is /dev/cd0):
# installp -aXYgd /dev/cd0 -e /tmp/install.log clic.rte.lib
# installp -aXYgd /dev/cd0 -e /tmp/install.log clic.rte.kernext

Run the follow command to initialize and enable EFS on the system:
# efsenable -a

To create a new EFS-enabled JFS2 file system and mount the file system, using the following commands:
# crfs -v jfs2 -g rootvg -m /fs2 -a size=100M -a efs=yes
# mount /fs2

To enable EFS on a JFS2 file system (like, /fs3), run the following command:
chfs -a efs=yes /fs3'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16481r294300_chk'
  tag severity: 'medium'
  tag gid: 'V-215283'
  tag rid: 'SV-215283r853470_rule'
  tag stig_id: 'AIX7-00-002096'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16479r294301_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000405-GPOS-00184', 'SRG-OS-000404-GPOS-00183']
  tag 'documentable'
  tag legacy: ['V-91723', 'SV-101821']
  tag cci: ['CCI-000366', 'CCI-002475', 'CCI-002476']
  tag nist: ['CM-6 b', 'SC-28 (1)', 'SC-28 (1)']
end
