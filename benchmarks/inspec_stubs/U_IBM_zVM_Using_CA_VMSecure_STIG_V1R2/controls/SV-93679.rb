control 'SV-93679' do
  title 'IBM z/VM must employ a Session manager.'
  desc 'A session manager controls the semi-permanent interactive information interchange, also known as a dialogue, between a user and z/VM. Without the use of a session manager these semi-permanent interchanges can be open to compromise and attacks.'
  desc 'check', 'Examine running systems.

If access is gained to the z/VM system without going through a session manager, this is a finding.'
  desc 'fix', 'Ensure that a session manager is in use with the system.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78561r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78973'
  tag rid: 'SV-93679r1_rule'
  tag stig_id: 'IBMZ-VM-002330'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-85723r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
