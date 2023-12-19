control 'SV-26571' do
  title 'The at.allow file must be group-owned by root, sys, bin or other.'
  desc 'If the group-owner of the at.allow file is not set to root, sys, bin or other, unauthorized users could be allowed to view or edit the list of users permitted to run at jobs. Unauthorized modification could result in Denial of Service to authorized at users or provide unauthorized users with the ability to run at jobs.'
  desc 'check', 'Check the group ownership of the file.

Procedure:
# ls -lL /usr/lib/cron/at.allow

If the file is not group-owned by root, sys, bin or other, this 
is a finding.'
  desc 'fix', 'Change the group ownership of the file.
# chgrp root /usr/lib/cron/at.allow'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36484r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22397'
  tag rid: 'SV-26571r1_rule'
  tag stig_id: 'GEN003470'
  tag gtitle: 'GEN003470'
  tag fix_id: 'F-31835r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
