control 'SV-26574' do
  title 'The at.deny file must be group-owned by root, bin, sys, or other.'
  desc 'If the group-owner of the at.deny file is not set to root, bin, sys, other, or cron, unauthorized users could be allowed to view or edit sensitive information contained within the file. Unauthorized modification could result in Denial of Service to authorized at users or provide unauthorized users with the ability to run at jobs.'
  desc 'fix', 'Change the group ownership of the at.deny file to root, 
bin, sys, or other.
# chgrp root /usr/lib/cron/at.deny'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22398'
  tag rid: 'SV-26574r1_rule'
  tag stig_id: 'GEN003490'
  tag gtitle: 'GEN003490'
  tag fix_id: 'F-31838r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
