control 'SV-4365' do
  title 'The "at" directory must be owned by root, bin, or sys.'
  desc 'If the owner of the "at" directory is not root, bin, or sys, unauthorized users could be allowed to view or edit files containing sensitive information within the directory.'
  desc 'check', 'Check the ownership of the "at" directory.

Procedure:
# ls -ld /var/spool/cron/atjobs /var/spool/atjobs /var/spool/at

If the directory is not owned by root, sys, bin, daemon, or cron, this is a finding.'
  desc 'fix', 'Change the owner of the "at" directory to root, bin, sys, or system.

Procedure:
# chown root /var/spool/at

(Replace root with another system group and/or /var/spool/at with a different "at" directory as necessary.)'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8246r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4365'
  tag rid: 'SV-4365r2_rule'
  tag stig_id: 'GEN003420'
  tag gtitle: 'GEN003420'
  tag fix_id: 'F-4276r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
