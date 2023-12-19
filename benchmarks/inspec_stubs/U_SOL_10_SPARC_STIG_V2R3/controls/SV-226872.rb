control 'SV-226872' do
  title 'The at.allow file must be group-owned by root, bin, or sys.'
  desc 'If the group owner of the at.allow file is not set to root, bin, or sys, unauthorized users could be allowed to view or edit the list of users permitted to run at jobs.  Unauthorized modification could result in Denial of Service to authorized at users or provide unauthorized users with the ability to run at jobs.'
  desc 'check', 'Check the group ownership of the file.

Procedure:
# ls -lL /etc/cron.d/at.allow

If the file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group ownership of the file.

Procedure:
# chgrp root /etc/cron.d/at.allow'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29034r484900_chk'
  tag severity: 'medium'
  tag gid: 'V-226872'
  tag rid: 'SV-226872r603265_rule'
  tag stig_id: 'GEN003470'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29022r484901_fix'
  tag 'documentable'
  tag legacy: ['SV-26570', 'V-22397']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
