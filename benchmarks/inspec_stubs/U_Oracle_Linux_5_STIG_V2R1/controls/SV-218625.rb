control 'SV-218625' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20100r562855_chk'
  tag severity: 'medium'
  tag gid: 'V-218625'
  tag rid: 'SV-218625r603259_rule'
  tag stig_id: 'GEN005740'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20098r562856_fix'
  tag 'documentable'
  tag legacy: ['V-928', 'SV-64237']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
