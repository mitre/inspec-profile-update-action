control 'SV-37527' do
  title 'The at directory must be owned by root, bin, sys, daemon, or cron.'
  desc 'If the owner of the "at" directory is not root, bin, or sys, unauthorized users could be allowed to view or edit files containing sensitive information within the directory.'
  desc 'check', 'Check the ownership of the "at" directory:

Procedure:
# ls -ld /var/spool/at

If the directory is not owned by root, sys, bin, daemon, or cron, this is a finding.'
  desc 'fix', 'Change the owner of the "at" directory to root, bin, sys, or system.

Procedure:
# chown <root or other system account> <"at" directory>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36186r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4365'
  tag rid: 'SV-37527r2_rule'
  tag stig_id: 'GEN003420'
  tag gtitle: 'GEN003420'
  tag fix_id: 'F-31441r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
