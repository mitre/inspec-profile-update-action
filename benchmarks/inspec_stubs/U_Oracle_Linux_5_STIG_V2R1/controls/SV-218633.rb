control 'SV-218633' do
  title 'The Network File System (NFS) server must not allow remote root access.'
  desc 'If the NFS server allows root access to local file systems from remote hosts, this access could be used to compromise the system.'
  desc 'check', 'List the exports.
# cat /etc/exports
If any export contains "no_root_squash" or does not contain "root_squash" or "all_squash", this is a finding.'
  desc 'fix', 'Edit the "/etc/exports" file and add "root_squash" (or "all_squash") and remove "no_root_squash".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20108r562876_chk'
  tag severity: 'medium'
  tag gid: 'V-218633'
  tag rid: 'SV-218633r603259_rule'
  tag stig_id: 'GEN005880'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-20106r562877_fix'
  tag 'documentable'
  tag legacy: ['V-935', 'SV-64157']
  tag cci: ['CCI-000225', 'CCI-000770']
  tag nist: ['AC-6', 'IA-2 (5)']
end
