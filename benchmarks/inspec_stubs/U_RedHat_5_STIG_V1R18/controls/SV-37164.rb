control 'SV-37164' do
  title 'The /etc/gshadow file must be group-owned by root.'
  desc 'The /etc/gshadow file is critical to system security and must be protected from unauthorized modification.   The /etc/gshadow file contains a list of system groups and hashes for group passwords.'
  desc 'check', 'Check the /etc/gshadow file is group-owned by root.
# ls -l /etc/gshadow
If the file is not group-owned by root, this is a finding.'
  desc 'fix', 'Change the group-owner of the /etc/gshadow file to root.
# chgrp root /etc/gshadow'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35871r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22342'
  tag rid: 'SV-37164r1_rule'
  tag stig_id: 'GEN000000-LNX001432'
  tag gtitle: 'GEN000000-LNX001432'
  tag fix_id: 'F-31125r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
