control 'SV-95549' do
  title 'AAA Services must be configured to notify the system administrators and ISSO when accounts are modified.'
  desc 'When application accounts are modified, user accessibility is affected. Accounts are utilized for identifying individual users or for identifying the application processes themselves. Sending notification of account modification events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.

AAA Services may not have built-in capabilities to notify the administrators and ISSO and may require the use of third-party tools (e.g. SNMP, SIEM) to perform the notification.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. 

Verify AAA Services are configured to notify the system administrators and ISSO when accounts are modified.

If AAA Services are not configured to notify the system administrators and ISSO when accounts are modified, this is a finding.'
  desc 'fix', 'Configure AAA Services to notify the system administrators and ISSO when accounts are modified.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80575r3_chk'
  tag severity: 'medium'
  tag gid: 'V-80839'
  tag rid: 'SV-95549r1_rule'
  tag stig_id: 'SRG-APP-000292-AAA-000140'
  tag gtitle: 'SRG-APP-000292-AAA-000140'
  tag fix_id: 'F-87693r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
