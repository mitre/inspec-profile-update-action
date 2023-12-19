control 'SV-222406' do
  title 'The application must ensure messages are encrypted when the SessionIndex is tied to privacy data.'
  desc 'When the SessionIndex is tied to privacy data (e.g., attributes containing privacy data) the message should be encrypted. If the message is not encrypted there is the possibility of compromise of privacy data.'
  desc 'check', 'Ask the application representative for the design document.

Review the design document for web services using SAML assertions.

If the application does not utilize SAML assertions, this check is not applicable.

Examine the contents of a SOAP message using a SessionIndex in the SAML element AuthnStatement. Verify the information which is tied to the SessionIndex.

If the SessionIndex is tied to privacy information, and it is not encrypted, this is a finding.'
  desc 'fix', 'Encrypt messages when the SessionIndex is tied to privacy data.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24076r493126_chk'
  tag severity: 'medium'
  tag gid: 'V-222406'
  tag rid: 'SV-222406r879519_rule'
  tag stig_id: 'APSC-DV-000260'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-24065r493127_fix'
  tag 'documentable'
  tag legacy: ['SV-83915', 'V-69293']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
