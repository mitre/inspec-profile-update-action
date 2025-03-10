control 'SV-927' do
  title 'NFS servers must only accept NFS requests from privileged ports on client systems.'
  desc 'If clients are not required to use privileged ports to get NFS services, then exported file systems may be in danger of mounting by malicious users and intruders that do not have access to privileged ports.'
  desc 'check', 'Determine if the NFS service accepts requests from unprivileged ports.  If it does, this is a finding.'
  desc 'fix', 'Configure the system to not accept NFS requests from unprivileged ports.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-854r2_chk'
  tag severity: 'medium'
  tag gid: 'V-28440'
  tag rid: 'SV-927r2_rule'
  tag stig_id: 'GEN005720'
  tag gtitle: 'GEN005720'
  tag fix_id: 'F-1081r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001465']
  tag nist: ['AC-20 b']
end
