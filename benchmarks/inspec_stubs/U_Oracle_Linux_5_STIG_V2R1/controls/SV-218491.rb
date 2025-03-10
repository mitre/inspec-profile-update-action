control 'SV-218491' do
  title 'A separate file system must be used for user home directories (such as /home or an equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Determine if the /home path is a separate filesystem.
# grep "/home " /etc/fstab
If no result is returned, /home is not on a separate filesystem this is a finding.'
  desc 'fix', 'Migrate the /home (or equivalent) path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19966r562609_chk'
  tag severity: 'low'
  tag gid: 'V-218491'
  tag rid: 'SV-218491r603259_rule'
  tag stig_id: 'GEN003620'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19964r562610_fix'
  tag 'documentable'
  tag legacy: ['V-12003', 'SV-64215']
  tag cci: ['CCI-000366', 'CCI-001208']
  tag nist: ['CM-6 b', 'SC-32']
end
