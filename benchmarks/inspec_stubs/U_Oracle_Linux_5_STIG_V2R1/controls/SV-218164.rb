control 'SV-218164' do
  title 'The /etc/gshadow file must be group-owned by root.'
  desc 'The /etc/gshadow file is critical to system security and must be protected from unauthorized modification.   The /etc/gshadow file contains a list of system groups and hashes for group passwords.'
  desc 'check', 'Check the /etc/gshadow file is group-owned by root.
# ls -l /etc/gshadow
If the file is not group-owned by root, this is a finding.'
  desc 'fix', 'Change the group-owner of the /etc/gshadow file to root.
# chgrp root /etc/gshadow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19639r561452_chk'
  tag severity: 'medium'
  tag gid: 'V-218164'
  tag rid: 'SV-218164r603259_rule'
  tag stig_id: 'GEN000000-LNX001432'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19637r561453_fix'
  tag 'documentable'
  tag legacy: ['V-22342', 'SV-62681']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
