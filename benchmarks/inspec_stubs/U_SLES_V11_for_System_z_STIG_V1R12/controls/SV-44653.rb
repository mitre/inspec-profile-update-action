control 'SV-44653' do
  title 'The /etc/access.conf file must have a privileged group owner.'
  desc 'Depending on the access restrictions of the /etc/access.conf file, if the group owner were not a privileged group, it could endanger system security.'
  desc 'check', 'Check access configuration group ownership:

# ls -lL /etc/security/access.conf

If this file exists and has a group-owner that is not a privileged user, this is a finding.'
  desc 'fix', 'Use the chgrp command to ensure the group owner is root, sys, or bin.
For example:
# chgrp root /etc/security/access.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42157r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1054'
  tag rid: 'SV-44653r1_rule'
  tag stig_id: 'GEN000000-LNX00420'
  tag gtitle: 'GEN000000-LNX00420'
  tag fix_id: 'F-38108r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
