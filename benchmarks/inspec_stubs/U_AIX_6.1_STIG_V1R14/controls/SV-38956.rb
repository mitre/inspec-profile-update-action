control 'SV-38956' do
  title 'The NFS anonymous UID and GID must be configured to values without permissions.'
  desc 'When an NFS server is configured to deny remote root access, a selected UID and GID are used to handle requests from the remote root user.  The UID and GID should be chosen from the system to provide the appropriate level of non-privileged access.'
  desc 'check', "Check if the anon option is set correctly for exported file systems.

List exported file systems.
# exportfs -v 

Each of the exported file systems should include an entry for the 'anon=' option set to -1 or an equivalent (60001, 60002, 65534, or 65535).  If an appropriate 'anon=' setting is not present for an exported file system, this is a finding."
  desc 'fix', 'Edit /etc/exports and set the anon=-1 option for exported file systems without it. Re-export the file systems.   

# exportfs -a'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-863r2_chk'
  tag severity: 'medium'
  tag gid: 'V-932'
  tag rid: 'SV-38956r1_rule'
  tag stig_id: 'GEN005820'
  tag gtitle: 'GEN005820'
  tag fix_id: 'F-32338r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000062']
  tag nist: ['AC-14 (1)']
end
