control 'SV-86015' do
  title 'The CA API Gateway providing content filtering must prevent the download of prohibited mobile code.'
  desc 'Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.

This applies to mobile code that may originate either internal to or external from the enclave. Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient. Mobile code that must be prevented from downloading is identified in CCI-001166.

The CA API Gateway must block against code injection and SQL injection attacks, helping to prevent/deny any mobile code that is exhibiting unusual behavior by preventing the injection of prohibited code or incorrectly formatted SQL statements.'
  desc 'check', 'Open the CA API GW - Policy Manager. 

Double-click all Registered Services that require protection from downloading prohibited mobile code and verify the "Protect Against SQL Attacks" and "Protect Against Code Injection" Threat Protection Assertions are included as part of the policies and that the target message is the response. 

If the Threat Protection Assertions are not included, this is a finding.'
  desc 'fix', 'Open the CA API GW - Policy Manager. 

Double-click on the Registered Services that did not have the "Protect Against SQL Attacks" and "Protect Against Code Injection" Threat Protection Assertions added to their policies and add them from the list of Assertions after a "Route via..." Assertion in order to protect the downloaded response from malicious intent, such as code injections. 

Choose from the list of available protections for the Assertions to meet the appropriate organizational requirement for protection against prohibited mobile code.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71791r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71391'
  tag rid: 'SV-86015r1_rule'
  tag stig_id: 'CAGW-GW-000510'
  tag gtitle: 'SRG-NET-000289-ALG-000110'
  tag fix_id: 'F-77709r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
