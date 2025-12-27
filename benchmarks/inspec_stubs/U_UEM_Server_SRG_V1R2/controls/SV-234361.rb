control 'SV-234361' do
  title 'The UEM server must be configured to use DoD PKI for multifactor authentication. This requirement is included in SRG-APP-000149.'
  desc 'Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device. 

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards, such as the U.S. Government Personal Identity Verification card and the DoD common access card.

A privileged account is any information system account with authorizations of a privileged user. 

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.'
  desc 'check', 'Verify the UEM server uses DoD PKI for multifactor authentication.

If the UEM server does not use DoD PKI for multifactor authentication, this is a finding.'
  desc 'fix', 'Configure the UEM server to use DoD PKI for multifactor authentication.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37546r614093_chk'
  tag severity: 'medium'
  tag gid: 'V-234361'
  tag rid: 'SV-234361r879595_rule'
  tag stig_id: 'SRG-APP-000154-UEM-000088'
  tag gtitle: 'SRG-APP-000154'
  tag fix_id: 'F-37511r614094_fix'
  tag 'documentable'
  tag cci: ['CCI-001936']
  tag nist: ['IA-2 (6)']
end
