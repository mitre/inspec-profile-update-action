control 'SV-46117' do
  title 'The Network File System (NFS) export configuration file must be owned by root.'
  desc "Failure to give ownership of the NFS export configuration file to root provides the designated owner and possible unauthorized users with the potential to change system configuration which could weaken the system's security posture."
  desc 'check', 'Check the owner of the exports file.

Example:
# ls -lL /etc/exports

If the export configuration file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the exports file to root.

Example:
# chown root /etc/exports'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43374r1_chk'
  tag severity: 'medium'
  tag gid: 'V-928'
  tag rid: 'SV-46117r1_rule'
  tag stig_id: 'GEN005740'
  tag gtitle: 'GEN005740'
  tag fix_id: 'F-39458r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
