control 'SV-222399' do
  title 'Messages protected with WS_Security must use time stamps with creation and expiration times.'
  desc 'The lack of time stamps could lead to the eventual replay of the message, leaving the application susceptible to replay events which may result in an immediate loss of confidentiality.'
  desc 'check', 'Ask the application representative for the design document. Review the design document for web services using WS-Security tokens.

If the application does not utilize WS-Security tokens, this check is not applicable.

Examine the contents of a SOAP message using WS Security; all messages should contain time stamps, sequence numbers, and expiration.

If messages using WS Security do not contain time stamps, sequence numbers, and expiration, this is a finding.'
  desc 'fix', 'Design and configure applications using WS-Security messages to use time stamps with creation and expiration times and sequence numbers.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24069r493105_chk'
  tag severity: 'high'
  tag gid: 'V-222399'
  tag rid: 'SV-222399r508029_rule'
  tag stig_id: 'APSC-DV-000190'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-24058r493106_fix'
  tag 'documentable'
  tag legacy: ['V-69279', 'SV-83901']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
