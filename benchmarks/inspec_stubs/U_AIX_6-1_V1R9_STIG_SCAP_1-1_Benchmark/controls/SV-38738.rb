control 'SV-38738' do
  title 'All skeleton files (typically in /etc/skel) must be group-owned by security.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user start-up parameters and possibly jeopardize user files.'
  desc 'fix', 'Change the group owner of the skeleton file to security.

Procedure:
# chgrp security /etc/security/.profile /etc/security/mkuser.sys'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-22358'
  tag rid: 'SV-38738r1_rule'
  tag stig_id: 'GEN001830'
  tag gtitle: 'GEN001830'
  tag fix_id: 'F-32453r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
