control 'SV-39350' do
  title 'The at directory must be owned by root, bin, sys, daemon, or cron.'
  desc 'If the owner of the at directory is not root, bin, sys, daemon, or cron unauthorized users could be allowed to view or edit files containing sensitive information within the directory.'
  desc 'check', 'Check the ownership of the at directory. 
Procedure: 
# ls -ld /var/spool/cron/atjobs

If the directory is not owned by root, bin, sys, daemon, or cron, this is a finding.'
  desc 'fix', 'Change the owner of the at directory to root, bin, sys, daemon, or cron.
 
Procedure: 
# chown bin /var/spool/cron/atjobs'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38296r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4365'
  tag rid: 'SV-39350r1_rule'
  tag stig_id: 'GEN003420'
  tag gtitle: 'GEN003420'
  tag fix_id: 'F-33584r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
