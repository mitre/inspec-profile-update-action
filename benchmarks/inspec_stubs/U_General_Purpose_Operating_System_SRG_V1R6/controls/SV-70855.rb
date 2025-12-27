control 'SV-70855' do
  title 'The operating system must enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'Verify the operating system enforces a delay of at least 4 seconds between logon prompts following a failed logon attempt. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57165r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56595'
  tag rid: 'SV-70855r1_rule'
  tag stig_id: 'SRG-OS-000480-GPOS-00226'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-61491r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
