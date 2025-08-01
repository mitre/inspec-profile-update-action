control 'SV-34995' do
  title 'The at directory must be group-owned by root, bin, sys or other.'
  desc 'If the group of the at directory is not root, bin, sys or other, unauthorized users could be allowed to view or edit files containing sensitive information within the directory.'
  desc 'check', 'Check the group ownership of the file.

Procedure:
# ls -lLd /var/spool/cron/atjobs

If the file is not group-owned by root, bin, sys or other this is a finding.'
  desc 'fix', 'Change the group ownership of the file to root, bin, sys or other.

# chgrp root /var/spool/cron/atjobs'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36481r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22396'
  tag rid: 'SV-34995r1_rule'
  tag stig_id: 'GEN003430'
  tag gtitle: 'GEN003430'
  tag fix_id: 'F-31829r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
