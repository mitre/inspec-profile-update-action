control 'SV-233144' do
  title 'The container platform must notify system administrators and ISSO when accounts are modified.'
  desc 'When application accounts are modified, user accessibility is affected. Accounts are utilized for identifying individual users or for identifying the application processes themselves. Sending notification of account modification events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Review the container platform configuration to determine if system administrators and ISSO are notified when accounts are modified. 

If system administrators and ISSO are not notified, this is a finding.'
  desc 'fix', 'Configure the container platform to notify system administrators and ISSO when accounts are modified.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36080r599068_chk'
  tag severity: 'medium'
  tag gid: 'V-233144'
  tag rid: 'SV-233144r599509_rule'
  tag stig_id: 'SRG-APP-000292-CTR-000680'
  tag gtitle: 'SRG-APP-000292'
  tag fix_id: 'F-36048r599069_fix'
  tag 'documentable'
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
