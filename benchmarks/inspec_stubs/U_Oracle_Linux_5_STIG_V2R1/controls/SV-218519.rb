control 'SV-218519' do
  title 'The system must not have the finger service active.'
  desc "The finger service provides information about the system's users to network clients.  This information could expose more information for potential used in subsequent attacks."
  desc 'check', '# grep disable /etc/xinetd.d/finger
If the finger service is not disabled, this is a finding.'
  desc 'fix', 'Edit /etc/xinetd.d/finger and set "disable=yes"'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19994r562681_chk'
  tag severity: 'low'
  tag gid: 'V-218519'
  tag rid: 'SV-218519r603259_rule'
  tag stig_id: 'GEN003860'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-19992r562682_fix'
  tag 'documentable'
  tag legacy: ['V-4701', 'SV-64051']
  tag cci: ['CCI-000381', 'CCI-001551']
  tag nist: ['CM-7 a', 'AC-4']
end
