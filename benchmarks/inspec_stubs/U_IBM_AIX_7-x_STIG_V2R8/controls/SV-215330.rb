control 'SV-215330' do
  title 'AIX NFS server must be configured to restrict file system access to local hosts.'
  desc "The NFS access option limits user access to the specified level. This assists in protecting exported file systems. If access is not restricted, unauthorized hosts may be able to access the system's NFS exports."
  desc 'check', 'Check the permissions on exported NFS file systems by running command: 

# exportfs -v 
/export/shared -ro,access=10.17.76.74

If the exported file systems do not contain the "rw" or "ro" options specifying a list of hosts or networks, this is a finding.'
  desc 'fix', 'Edit "/etc/exports" and add "ro" and/or "rw" options (as appropriate) specifying a list of hosts or networks which are permitted access. 

Re-export the file systems:
# /usr/sbin/exportfs -a'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16528r294441_chk'
  tag severity: 'medium'
  tag gid: 'V-215330'
  tag rid: 'SV-215330r508663_rule'
  tag stig_id: 'AIX7-00-003017'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16526r294442_fix'
  tag 'documentable'
  tag legacy: ['SV-101741', 'V-91643']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
