control 'SV-215234' do
  title 'NFS file systems on AIX must be mounted with the nosuid option unless the NFS file systems contain approved setuid or setgid programs.'
  desc 'The nosuid mount option causes the system to not execute setuid files with owner privileges. This option must be used for mounting any file system not containing approved setuid files. Executing setuid files from untrusted file systems, or file systems not containing approved setuid files, increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Obtain a list of NFS file systems that contain approved "setuid" or "setgid" files from the ISSO/ISSM.

Check the "nosuid" mount option is used on all NFS file systems that do not contain approved "setuid" or "setgid" files: 
# mount | grep -E "options|nfs|---"
  node       mounted        mounted over    vfs       date        options 
-------- ---------------  ---------------  ------ ------------ --------------- 
ausgsa.ibm.com  /gsa/ausgsa/projects/a/aix/71  /mnt_1  nfs3   Nov 05 14:11  ro,bg,hard,intr,nosuid,sec=sys
ausgsa.ibm.com  /gsa/ausgsa/projects/a/aix/72  /mnt_2  nfs3   Nov 05 14:12  ro,bg,hard,intr,sec=sys

If the NFS mounts do not show the "nosuid" setting in their "options" fields, along with other mount options, this is a finding.'
  desc 'fix', 'For each NFS file systems that does not contain approved "setuid" or "setgid" files, add the "nosuid" option, along with other mount options, to the "options" field in "/etc/filesystems" using the following command:
# chfs -a options=ro,bg,hard,intr,nosuid,sec=sys <NFS_mount_point>

Note that the other mount options (other than the nosuid options) may be different among NFS mounts.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16432r294153_chk'
  tag severity: 'medium'
  tag gid: 'V-215234'
  tag rid: 'SV-215234r853460_rule'
  tag stig_id: 'AIX7-00-001138'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag fix_id: 'F-16430r294154_fix'
  tag 'documentable'
  tag legacy: ['V-91511', 'SV-101609']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
