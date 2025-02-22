control 'SV-218631' do
  title 'The Network File System (NFS) anonymous UID and GID must be configured to values without permissions.'
  desc 'When an NFS server is configured to deny remote root access, a selected UID and GID are used to handle requests from the remote root user.  The UID and GID should be chosen from the system to provide the appropriate level of non-privileged access.'
  desc 'check', %q(Check if the 'anonuid' and 'anongid' options are set correctly for exported file systems.

List exported filesystems:
# exportfs -v 

Each of the exported file systems should include an entry for the 'anonuid=' and 'anongid=' options set to "-1" or an equivalent (60001, 65534, or 65535).

If appropriate values for 'anonuid' or 'anongid' are not set, this is a finding.)
  desc 'fix', 'Edit "/etc/exports" and set the "anonuid=-1" and "anongid=-1" options for exports lacking it. 

Re-export the filesystems.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20106r562873_chk'
  tag severity: 'medium'
  tag gid: 'V-218631'
  tag rid: 'SV-218631r603259_rule'
  tag stig_id: 'GEN005820'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20104r562874_fix'
  tag 'documentable'
  tag legacy: ['V-932', 'SV-64169']
  tag cci: ['CCI-000062', 'CCI-002355']
  tag nist: ['AC-14 (1)', 'AC-24 (2)']
end
