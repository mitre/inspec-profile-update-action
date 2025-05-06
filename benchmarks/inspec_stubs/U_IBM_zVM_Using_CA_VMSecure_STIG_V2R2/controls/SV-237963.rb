control 'SV-237963' do
  title 'IBM z/VM must employ a Session manager.'
  desc 'A session manager controls the semi-permanent interactive information interchange, also known as a dialogue, between a user and z/VM. Without the use of a session manager these semi-permanent interchanges can be open to compromise and attacks.'
  desc 'check', 'Examine running systems.

If access is gained to the z/VM system without going through a session manager, this is a finding.'
  desc 'fix', 'Ensure that a session manager is in use with the system.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41173r649727_chk'
  tag severity: 'medium'
  tag gid: 'V-237963'
  tag rid: 'SV-237963r649729_rule'
  tag stig_id: 'IBMZ-VM-002330'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-41132r649728_fix'
  tag 'documentable'
  tag legacy: ['SV-93679', 'V-78973']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
