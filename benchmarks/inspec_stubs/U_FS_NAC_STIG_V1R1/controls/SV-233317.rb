control 'SV-233317' do
  title 'When devices fail the policy assessment, Forescout must create a record with sufficient detail suitable for forwarding to a remediation server for automated remediation or sending to the user for manual remediation.'
  desc 'Notifications sent to the user and/or network administrator informing them of remediation requirements will ensure that action is taken.'
  desc 'check', 'Verify Forescout sends user and/or admin notification of remediation requirements, whether manual or automated.

If the NAC does not flag for future manual or automated remediation, devices failing policy assessment that are not automatically remediated either before or during the remote access session, this a finding.'
  desc 'fix', 'Log on to the Forescout UI. 

1. Within the Policy tab, locate the Compliance policies. 
2. Within the policy Sub-Rule, ensure all policies that indicate remediation have been configured to notify the user and/or network administrator of required action.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36512r605654_chk'
  tag severity: 'medium'
  tag gid: 'V-233317'
  tag rid: 'SV-233317r611394_rule'
  tag stig_id: 'FORE-NC-000090'
  tag gtitle: 'SRG-NET-000015-NAC-000110'
  tag fix_id: 'F-36477r605655_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
