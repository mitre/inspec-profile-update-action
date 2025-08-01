control 'SV-95551' do
  title 'AAA Services must be configured to notify the system administrators and ISSO for account disabling actions.'
  desc 'When application accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual users or for identifying the application processes themselves. Sending notification of account disabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.

AAA Services may not have built-in capabilities to notify the administrators and ISSO and may require the use of third-party tools (e.g. SNMP, SIEM) to perform the notification.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. 

Verify AAA Services are configured to notify the system administrators and ISSO for account disabling actions.

If AAA Services are not configured to notify the system administrators and ISSO for account disabling actions, this is a finding.'
  desc 'fix', 'Configure AAA Services to notify system administrators and ISSO for account disabling actions.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80577r3_chk'
  tag severity: 'medium'
  tag gid: 'V-80841'
  tag rid: 'SV-95551r1_rule'
  tag stig_id: 'SRG-APP-000293-AAA-000150'
  tag gtitle: 'SRG-APP-000293-AAA-000150'
  tag fix_id: 'F-87695r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001685']
  tag nist: ['AC-2 (4)']
end
