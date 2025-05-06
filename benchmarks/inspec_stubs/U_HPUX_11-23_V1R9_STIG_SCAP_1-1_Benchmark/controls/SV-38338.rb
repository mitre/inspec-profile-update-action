control 'SV-38338' do
  title 'The /etc/group file must be group-owned by root, bin, sys, or system.'
  desc 'The /etc/group file is critical to system security and must be protected from unauthorized modification.  The group file contains a list of system groups and associated information.'
  desc 'fix', 'Change the group owner of the /etc/group file.

Procedure:
# chgrp root /etc/group'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22336'
  tag rid: 'SV-38338r1_rule'
  tag stig_id: 'GEN001392'
  tag gtitle: 'GEN001392'
  tag fix_id: 'F-31652r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
