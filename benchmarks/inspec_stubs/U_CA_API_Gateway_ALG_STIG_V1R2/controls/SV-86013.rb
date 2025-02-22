control 'SV-86013' do
  title 'The CA API Gateway providing content filtering must block or restrict detected prohibited mobile code.'
  desc 'Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.

This applies to mobile code that may originate either internal to or external from the enclave. Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient. Mobile code that must be blocked or restricted is identified in CCI-001166.

The CA API Gateway must block against code injection and SQL injection attacks, helping to block any mobile code that is exhibiting unusual behavior, such as the injection of incorrect code or wrongly formatted SQL statements, and that may be prohibited from use due to these anomalies.'
  desc 'check', 'Open the CA API Gateway - Policy Manager. 

Double-click all Registered Services that require protection from prohibited mobile code and verify the "Protect Against SQL Attacks" and "Protect Against Code Injection" Threat Protection Assertions are included as part of the policies. 

If they are not included, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager. 

Double-click on the Registered Services that did not have the "Protect Against SQL Attacks" and "Protect Against Code Injection" Threat Protection Assertions added to their policies and add them from the list of Assertions. 

Chose from the list of available protections for the Assertions to meet the appropriate organizational requirement for protection against prohibited mobile code.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71789r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71389'
  tag rid: 'SV-86013r1_rule'
  tag stig_id: 'CAGW-GW-000500'
  tag gtitle: 'SRG-NET-000288-ALG-000109'
  tag fix_id: 'F-77707r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
