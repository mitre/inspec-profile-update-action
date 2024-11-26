control 'SV-80357' do
  title 'Trend Deep Security must automatically audit account removal actions.'
  desc 'When application accounts are removed, user accessibility is affected. Accounts are utilized for identifying individual application users or for identifying the application processes themselves. In order to detect and respond to events affecting user accessibility and application processing, applications must audit account removal actions and, as required, notify the appropriate individuals, so they can investigate the event. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes. 

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/audit mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure account removal actions are automatically audited.

Verify "User Deleted" events are enabled by reviewing the following:
   
Administration >> System Settings >> System Events >> Enable Event ID 651  User Deleted.

Select: Record
Select: Forward

If "User Deleted"  is not enabled this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to automatically audit account removal actions.

Enable "User Deleted" events by selecting the following:

Administration >> System Settings >> System Events >> Enable Event ID 651  User Deleted.

Select: Record
Select: Forward'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66515r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65867'
  tag rid: 'SV-80357r1_rule'
  tag stig_id: 'TMDS-00-000035'
  tag gtitle: 'SRG-APP-000029'
  tag fix_id: 'F-71943r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
