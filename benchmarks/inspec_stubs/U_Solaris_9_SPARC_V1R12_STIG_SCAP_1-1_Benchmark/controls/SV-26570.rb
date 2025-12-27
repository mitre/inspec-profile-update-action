control 'SV-26570' do
  title 'The at.allow file must be group-owned by root, bin, or sys.'
  desc 'If the group owner of the at.allow file is not set to root, bin, or sys, unauthorized users could be allowed to view or edit the list of users permitted to run at jobs.  Unauthorized modification could result in Denial of Service to authorized at users or provide unauthorized users with the ability to run at jobs.'
  desc 'fix', 'Change the group ownership of the file.

Procedure:
# chgrp root /etc/cron.d/at.allow'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22397'
  tag rid: 'SV-26570r1_rule'
  tag stig_id: 'GEN003470'
  tag gtitle: 'GEN003470'
  tag fix_id: 'F-23816r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
