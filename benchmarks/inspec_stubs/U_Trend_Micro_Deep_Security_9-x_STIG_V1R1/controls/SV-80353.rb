control 'SV-80353' do
  title 'Trend Deep Security must automatically audit account modification.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply modify an existing account. Auditing of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail documents the creation of application user accounts and, as required, notifies administrators and/or application owners exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes. 

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure account creation is automatically audited.

Verify "User Updated" events is enabled by reviewing the following:

Administration >> System Settings >> System Events >> Enable Event ID 652  User Updated.

Select: Record
Select: Forward

If "User Updated" is not enabled this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to automatically audit account creation.

Enable "User Updated" events by selecting the following:

Administration >> System Settings >> System Events >> Enable Event ID 652  User Updated.

Select: Record
Select: Forward'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66511r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65863'
  tag rid: 'SV-80353r1_rule'
  tag stig_id: 'TMDS-00-000025'
  tag gtitle: 'SRG-APP-000027'
  tag fix_id: 'F-71939r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
