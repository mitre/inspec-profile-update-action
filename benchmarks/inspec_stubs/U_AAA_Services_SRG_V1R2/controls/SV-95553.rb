control 'SV-95553' do
  title 'AAA Services must be configured to notify the system administrators and ISSO for account removal actions.'
  desc 'When application accounts are removed, user accessibility is affected. Accounts are utilized for identifying users or for identifying the application processes themselves. Sending notification of account removal events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.

AAA Services may not have built-in capabilities to notify system administrators and ISSO and may require the use of third-party tools (e.g. SNMP, SIEM) to perform the notification.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. 

Verify AAA Services are configured to notify the system administrators and ISSO for account removal actions.

If AAA Services are not configured to notify the system administrators and ISSO for account removal actions, this is a finding.'
  desc 'fix', 'Configure AAA Services to notify system administrators and ISSO for account removal actions.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80579r4_chk'
  tag severity: 'medium'
  tag gid: 'V-80843'
  tag rid: 'SV-95553r1_rule'
  tag stig_id: 'SRG-APP-000294-AAA-000160'
  tag gtitle: 'SRG-APP-000294-AAA-000160'
  tag fix_id: 'F-87697r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001686']
  tag nist: ['AC-2 (4)']
end
