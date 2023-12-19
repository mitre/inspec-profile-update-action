control 'SV-44658' do
  title 'The Linux NFS Server must not have the insecure file locking option.'
  desc 'Insecure file locking could allow for sensitive data to be viewed or edited by an unauthorized user.'
  desc 'check', 'Determine if an NFS server is running on the system by:

# ps -ef |grep nfsd

If an NFS server is running, confirm it is not configured with the insecure_locks option by:

# exportfs -v

The example below would be a finding:

/misc/export speedy.example.com(rw,insecure_locks)'
  desc 'fix', 'Remove the "insecure_locks" option from all NFS exports on the system.'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42162r1_chk'
  tag severity: 'high'
  tag gid: 'V-4339'
  tag rid: 'SV-44658r1_rule'
  tag stig_id: 'GEN000000-LNX00560'
  tag gtitle: 'GEN000000-LNX00560'
  tag fix_id: 'F-38113r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225', 'CCI-000764']
  tag nist: ['AC-6', 'IA-2']
end
