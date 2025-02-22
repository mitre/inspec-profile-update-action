control 'SV-95547' do
  title 'AAA Services must be configured to notify the system administrators and ISSO when accounts are created.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply create a new account. Sending notification of account creation events to the system administrator and ISSO is one method for mitigating this risk. 

AAA Services may not have built-in capabilities to notify the administrators and ISSO and may require the use of third-party tools (e.g. SNMP, SIEM) to perform the notification.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. 

Verify AAA Services are configured to notify the system administrators and ISSO when accounts are created.

If AAA Services are not configured to notify the system administrators and ISSO when accounts are created, this is a finding.'
  desc 'fix', 'Configure AAA Services to notify the system administrators and ISSO when accounts are created.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80573r4_chk'
  tag severity: 'medium'
  tag gid: 'V-80837'
  tag rid: 'SV-95547r1_rule'
  tag stig_id: 'SRG-APP-000291-AAA-000130'
  tag gtitle: 'SRG-APP-000291-AAA-000130'
  tag fix_id: 'F-87691r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001683']
  tag nist: ['AC-2 (4)']
end
