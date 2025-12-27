control 'SV-203783' do
  title 'The operating system must limit the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders.'
  desc "Users' home directories/folders may contain information of a sensitive nature. Non-privileged users should coordinate any sharing of information with an SA through shared resources."
  desc 'check', 'Verify the operating system limits the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to limit the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3908r375740_chk'
  tag severity: 'medium'
  tag gid: 'V-203783'
  tag rid: 'SV-203783r388482_rule'
  tag stig_id: 'SRG-OS-000480-GPOS-00230'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-3908r375741_fix'
  tag 'documentable'
  tag legacy: ['V-56583', 'SV-70843']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
