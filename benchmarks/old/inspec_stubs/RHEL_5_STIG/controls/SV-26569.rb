control 'SV-26569' do
  title 'The at.allow file must be group-owned by root, bin, sys, or cron.'
  desc 'If the group owner of the at.allow file is not set to root, bin, sys, or cron, unauthorized users could be allowed to view or edit the list of users permitted to run "at" jobs.  Unauthorized modification could result in Denial of Service to authorized "at" users or provide unauthorized users with the ability to run "at" jobs.'
  desc 'fix', 'Change the group ownership of the file.

Procedure:
# chgrp root /etc/at.allow'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22397'
  tag rid: 'SV-26569r1_rule'
  tag stig_id: 'GEN003470'
  tag gtitle: 'GEN003470'
  tag fix_id: 'F-31450r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
