control 'SV-246922' do
  title 'ONTAP must be configured to limit the number of concurrent sessions.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.'
  desc 'check', 'Use "security session limit show -interface cli" to check the concurrent session limit.

If the security session limit is not configured to limit the number of concurrent sessions to 1, this is a finding.'
  desc 'fix', 'Configure session limits with the command, “security session limit modify -max-active-limit 1 -interface cli -category application".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50354r769096_chk'
  tag severity: 'medium'
  tag gid: 'V-246922'
  tag rid: 'SV-246922r769098_rule'
  tag stig_id: 'NAOT-AC-000001'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-50308r769097_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
