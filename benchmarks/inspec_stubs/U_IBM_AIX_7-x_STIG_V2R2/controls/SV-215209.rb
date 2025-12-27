control 'SV-215209' do
  title 'All AIX NFS anonymous UIDs and GIDs must be configured to values without permissions.'
  desc 'When an NFS server is configured to deny remote root access, a selected UID and GID are used to handle requests from the remote root user. The UID and GID should be chosen from the system to provide the appropriate level of non-privileged access.'
  desc 'check', 'Check if the "anon" option is set correctly for exported file systems. 

List exported file systems using command: 

# exportfs -v 
/home/doej     rw,anon=-1,access=doej

Note: Each of the exported file systems should include an entry for the "anon=" option set to "-1" or an equivalent (60001, 60002, 65534, or 65535). 

If an appropriate "anon=" setting is not present for an exported file system, this is a finding.'
  desc 'fix', 'Edit "/etc/exports" and set the "anon=-1" option for all exported file systems without it. 

Re-export the file systems using command: 
# exportfs -a'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16407r294078_chk'
  tag severity: 'medium'
  tag gid: 'V-215209'
  tag rid: 'SV-215209r508663_rule'
  tag stig_id: 'AIX7-00-001055'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16405r294079_fix'
  tag 'documentable'
  tag legacy: ['V-91591', 'SV-101689']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
