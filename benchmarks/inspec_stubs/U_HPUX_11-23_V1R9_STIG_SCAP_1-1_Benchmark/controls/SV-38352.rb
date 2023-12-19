control 'SV-38352' do
  title 'All shell files must be group-owned by root, bin, sys, or system.'
  desc 'If shell files are group-owned by users other than root or a system group, they could be modified by intruders or malicious users to perform unauthorized actions.'
  desc 'fix', 'Change the group owner of the shell to root, bin, sys, or other.


Procedure:
# chgrp root <shell>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22365'
  tag rid: 'SV-38352r1_rule'
  tag stig_id: 'GEN002210'
  tag gtitle: 'GEN002210'
  tag fix_id: 'F-31734r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
