control 'SV-222400' do
  title 'Validity periods must be verified on all application messages using WS-Security or SAML assertions.'
  desc 'When using WS-Security in SOAP messages, the application should check the validity of the time stamps with creation and expiration times. Time stamps that are not validated may lead to a replay event and provide immediate unauthorized access of the application. Unauthorized access results in an immediate loss of confidentiality.'
  desc 'check', 'Ask the application representative for the design document.

Review the design document for web services.

If the application does not utilize WSS or SAML assertions, this requirement is not applicable.

Review the design document and verify validity periods are checked on all messages using WS-Security or SAML assertions.

If the design document does not exist, or does not indicate validity periods are checked on messages using WS-Security or SAML assertions, this is a finding.'
  desc 'fix', 'Design and configure the application to use validity periods, ensure validity periods are verified on all WS-Security token profiles and SAML Assertions.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24070r493108_chk'
  tag severity: 'high'
  tag gid: 'V-222400'
  tag rid: 'SV-222400r508029_rule'
  tag stig_id: 'APSC-DV-000200'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-24059r493109_fix'
  tag 'documentable'
  tag legacy: ['SV-83903', 'V-69281']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
