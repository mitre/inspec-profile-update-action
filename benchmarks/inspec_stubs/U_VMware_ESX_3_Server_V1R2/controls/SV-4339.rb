control 'SV-4339' do
  title 'The Linux NFS Server must not have the insecure file locking option.'
  desc 'Insecure file locking could allow for sensitive data to be viewed or edited by an unauthorized user.'
  desc 'check', 'Determine if an NFS server is running on the system by:
	
	#	ps –ef |grep nfsd

If an NFS server is running, confirm that it is not configured with the insecure_locks option by:

	#	exportfs –v

The example below would be a finding:

	/misc/export	speedy.example.com(rw,insecure_locks)'
  desc 'fix', 'Remove the "insecure_locks" option from all NFS exports on the system.

Procedure:

Edit /etc/exports and remove all instances of the insecure_locks option.

Re-export the file systems to make the setting take effect.
# exportfs -a'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2150r2_chk'
  tag severity: 'high'
  tag gid: 'V-4339'
  tag rid: 'SV-4339r2_rule'
  tag stig_id: 'GEN000000-LNX00560'
  tag gtitle: 'GEN000000-LNX00560'
  tag fix_id: 'F-4250r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000225', 'CCI-000764']
  tag nist: ['AC-6', 'IA-2']
end
