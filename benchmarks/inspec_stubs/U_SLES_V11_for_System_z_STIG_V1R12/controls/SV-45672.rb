control 'SV-45672' do
  title 'The atjobs directory must be owned by root, bin, daemon or at.'
  desc 'If the owner of the "atjobs" directory is not root, bin, daemon or at, unauthorized users could be allowed to view or edit files containing sensitive information within the directory.'
  desc 'check', 'Check the ownership of the "at" directory:

Procedure:
# ls -ld /var/spool/atjobs

If the directory is not owned by root, bin, daemon, or at, this is a finding.'
  desc 'fix', 'Change the owner of the "atjobs" directory to root, bin, daemon or at.

Procedure:
# chown <root|bin|daemon|at> <"atjobs" directory>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43038r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4365'
  tag rid: 'SV-45672r2_rule'
  tag stig_id: 'GEN003420'
  tag gtitle: 'GEN003420'
  tag fix_id: 'F-39070r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
