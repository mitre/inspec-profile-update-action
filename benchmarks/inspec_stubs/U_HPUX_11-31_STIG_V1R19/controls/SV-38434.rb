control 'SV-38434' do
  title 'The at directory must be owned by root, bin, or sys.'
  desc 'If the owner of the at directory is not root, bin, or sys, unauthorized users could be allowed to view or edit files containing sensitive information within the directory.'
  desc 'check', 'Check the ownership of the at directory:
# ls -lLd /var/spool/cron/atjobs /var/spool/atjobs /var/spool/at

If the directory exists and is not owned by root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the owner of the existing at directory to root, bin, or sys.
# chown root <at directory>

(Replace root with another system group and/or <at directory> with a different at directory as necessary.)'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36467r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4365'
  tag rid: 'SV-38434r1_rule'
  tag stig_id: 'GEN003420'
  tag gtitle: 'GEN003420'
  tag fix_id: 'F-31809r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
