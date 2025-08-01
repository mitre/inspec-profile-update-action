control 'SV-68583' do
  title 'The ALG providing user access control intermediary services must limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types.'
  desc 'Network element management includes the ability to control the number of users and user sessions that utilize a network element. Limiting the number of current sessions per user is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions must be the same as the requirements specified for the application for which it serves as intermediary.

This policy only applies to application gateways/firewalls (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', 'If the ALG does not provide user access control intermediary services, this is not applicable.

Verify the ALG limits the number of concurrent sessions to an organization-defined number for all accounts and/or account types.

If the ALG does not limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG to limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-54953r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54337'
  tag rid: 'SV-68583r1_rule'
  tag stig_id: 'SRG-NET-000053-ALG-000001'
  tag gtitle: 'SRG-NET-000053-ALG-000001'
  tag fix_id: 'F-59191r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
