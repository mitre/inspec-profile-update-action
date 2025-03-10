control 'SV-95661' do
  title 'AAA Services must be configured to automatically remove temporary user accounts after 72 hours.'
  desc 'When temporary user accounts remain active after no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary user accounts must be set upon account creation. Disabling a temporary account provides a higher risk alternative; disabling allows an insider adversary to enable the privileged account and make it permanent.

Temporary accounts, when used, mandate that AAA Services must be configured to automatically terminate these types of accounts after 72 hours. When AAA Services do not perform account management, the connected Active Directory must provide this setting.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. 

Verify AAA Services are configured to automatically remove temporary user accounts after 72 hours.

If the AAA Services configuration does not automatically remove temporary user accounts after 72 hours, this is a finding.'
  desc 'fix', 'Configure AAA Services to automatically remove temporary user accounts after 72 hours.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80689r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80951'
  tag rid: 'SV-95661r1_rule'
  tag stig_id: 'SRG-APP-000024-AAA-000040'
  tag gtitle: 'SRG-APP-000024-AAA-000040'
  tag fix_id: 'F-87807r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
end
