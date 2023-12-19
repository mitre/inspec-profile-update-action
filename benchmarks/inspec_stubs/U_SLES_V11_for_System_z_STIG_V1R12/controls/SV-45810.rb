control 'SV-45810' do
  title 'The system must not have the finger service active.'
  desc "The finger service provides information about the system's users to network clients.  This information could expose more information for potential used in subsequent attacks."
  desc 'check', '# grep disable /etc/xinetd.d/finger
If the finger service is not disabled, this is a finding.'
  desc 'fix', 'Edit /etc/xinetd.d/finger and set "disable=yes"'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43131r1_chk'
  tag severity: 'low'
  tag gid: 'V-4701'
  tag rid: 'SV-45810r1_rule'
  tag stig_id: 'GEN003860'
  tag gtitle: 'GEN003860'
  tag fix_id: 'F-39200r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
