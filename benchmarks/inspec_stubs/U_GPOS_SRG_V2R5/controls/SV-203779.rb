control 'SV-203779' do
  title 'The operating system must enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'Verify the operating system enforces a delay of at least 4 seconds between logon prompts following a failed logon attempt. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3904r375728_chk'
  tag severity: 'medium'
  tag gid: 'V-203779'
  tag rid: 'SV-203779r388482_rule'
  tag stig_id: 'SRG-OS-000480-GPOS-00226'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-3904r375729_fix'
  tag 'documentable'
  tag legacy: ['SV-70855', 'V-56595']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
