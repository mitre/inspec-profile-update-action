control 'SV-39180' do
  title 'The ftpusers file must be group-owned by bin, sys, or system.'
  desc 'If the ftpusers file is not group-owned by a system group, an unauthorized user may modify the file to allow unauthorized accounts to use FTP.'
  desc 'fix', 'Change the group owner of the ftpusers file.

Procedure:
# chgrp system /etc/ftpusers'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-22444'
  tag rid: 'SV-39180r1_rule'
  tag stig_id: 'GEN004930'
  tag gtitle: 'GEN004930'
  tag fix_id: 'F-33434r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
