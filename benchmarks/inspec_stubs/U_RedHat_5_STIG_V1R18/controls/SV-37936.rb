control 'SV-37936' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37200r1_chk'
  tag severity: 'medium'
  tag gid: 'V-928'
  tag rid: 'SV-37936r1_rule'
  tag stig_id: 'GEN005740'
  tag gtitle: 'GEN005740'
  tag fix_id: 'F-32428r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
