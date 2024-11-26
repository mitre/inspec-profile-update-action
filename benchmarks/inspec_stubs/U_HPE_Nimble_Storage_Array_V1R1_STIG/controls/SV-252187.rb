control 'SV-252187' do
  title 'The HPE Nimble must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must block any login attempt for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Type "userpolicy --info" and review output for line: "Number of authentication attempts". If the value is 2 or less, this is not a finding.'
  desc 'fix', 'Type "userpolicy --edit --allowed_attempts 2".'
  impact 0.5
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55643r814039_chk'
  tag severity: 'medium'
  tag gid: 'V-252187'
  tag rid: 'SV-252187r814041_rule'
  tag stig_id: 'HPEN-NM-000020'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-55593r814040_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
