control 'SV-233157' do
  title 'The container platform must automatically audit account-enabling actions.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Automatically auditing account enabling actions provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Determine if the container platform is configured to automatically audit account-enabling actions. 

If the container platform is not configured to automatically audit account-enabling actions, this is a finding.'
  desc 'fix', 'Configure the container platform to automatically audit account-enabling actions.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36093r599107_chk'
  tag severity: 'medium'
  tag gid: 'V-233157'
  tag rid: 'SV-233157r599509_rule'
  tag stig_id: 'SRG-APP-000319-CTR-000745'
  tag gtitle: 'SRG-APP-000319'
  tag fix_id: 'F-36061r599108_fix'
  tag 'documentable'
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
