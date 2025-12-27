control 'SV-70843' do
  title 'The operating system must limit the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders.'
  desc "Users' home directories/folders may contain information of a sensitive nature. Non-privileged users should coordinate any sharing of information with an SA through shared resources."
  desc 'check', 'Verify the operating system limits the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to limit the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57155r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56583'
  tag rid: 'SV-70843r1_rule'
  tag stig_id: 'SRG-OS-000480-GPOS-00230'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-61481r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
