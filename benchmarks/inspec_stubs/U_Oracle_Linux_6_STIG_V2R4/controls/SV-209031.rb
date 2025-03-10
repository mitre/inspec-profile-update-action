control 'SV-209031' do
  title 'The NFS server must not have the insecure file locking option enabled.'
  desc 'Allowing insecure file locking could allow for sensitive data to be viewed or edited by an unauthorized user.'
  desc 'check', 'To verify insecure file locking has been disabled, run the following command: 

# grep insecure_locks /etc/exports

If there is output, this is a finding.'
  desc 'fix', 'By default the NFS server requires secure file-lock requests, which require credentials from the client in order to lock a file. Most NFS clients send credentials with file lock requests, however, there are a few clients that do not send credentials when requesting a file-lock, allowing the client to only be able to lock world-readable files.

To get around this, the "insecure_locks" option can be used so these clients can access the desired export.

This poses a security risk by potentially allowing the client access to data for which it does not have authorization.

Remove any instances of the "insecure_locks" option from the file "/etc/exports".'
  impact 0.7
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9284r357878_chk'
  tag severity: 'high'
  tag gid: 'V-209031'
  tag rid: 'SV-209031r603263_rule'
  tag stig_id: 'OL6-00-000309'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-9284r357879_fix'
  tag 'documentable'
  tag legacy: ['V-51047', 'SV-65253']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
