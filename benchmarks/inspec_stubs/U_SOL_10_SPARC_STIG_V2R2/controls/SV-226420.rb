control 'SV-226420' do
  title 'The NFS server must have logging implemented.'
  desc 'Filesystem logging, especially for NFS exported file systems, can be critical to detecting data misuse and possible hardware/system errors that may, otherwise, go unnoticed.'
  desc 'check', 'To enable NFS server logging the log option must be applied to all exported file systems in the /etc/dfs/dfstab. Perform the following to verify NFS is enabled.

      #       share

The preceding command will display all exported filesystems. Each line should contain a log entry to indicate logging is enabled. If the log entry is not present, this is a finding. If the share command does not return anything, then this is not an NFS server and this is considered not applicable.

NFS version 4 does not support server logging.  Verify NFS_SERVER_VERSMAX in /etc/default/nfs.

# grep NFS_SERVER_VERSMAX /etc/default/nfs

If NFS_SERVER_VERSMAX is commented out or set to any value but 2 or 3, this is a finding.'
  desc 'fix', 'Edit /etc/dfs/dfstab and add the log option to all exported filesystems. Run the shareall command for the changes to take effect.

NFS version 2 or 3 must be forced by updating the NFS_SERVER_VERSMAX variable appropriately in /etc/default/nfs and restarting the NFS daemon.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36369r602710_chk'
  tag severity: 'medium'
  tag gid: 'V-226420'
  tag rid: 'SV-226420r603265_rule'
  tag stig_id: 'GEN000000-SOL00400'
  tag gtitle: 'SRG-OS-000470'
  tag fix_id: 'F-36333r602711_fix'
  tag 'documentable'
  tag legacy: ['V-4300', 'SV-40041']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
