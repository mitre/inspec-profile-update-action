control 'SV-218163' do
  title 'The /etc/gshadow file must be owned by root.'
  desc 'The /etc/gshadow file is critical to system security and must be owned by a privileged user.  The /etc/gshadow file contains a list of system groups and hashes for group passwords.'
  desc 'check', 'Check the /etc/gshadow file is owned by root.
# ls -l /etc/gshadow
If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/gshadow file to root.
# chown root /etc/gshadow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19638r561449_chk'
  tag severity: 'medium'
  tag gid: 'V-218163'
  tag rid: 'SV-218163r603259_rule'
  tag stig_id: 'GEN000000-LNX001431'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19636r561450_fix'
  tag 'documentable'
  tag legacy: ['V-22341', 'SV-62667']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
