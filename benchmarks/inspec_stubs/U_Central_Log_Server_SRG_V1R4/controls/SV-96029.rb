control 'SV-96029' do
  title 'The Central Log Server must be configured to use multifactor authentication for network access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access.'
  desc 'Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device. 

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards, such as the U.S. Government Personal Identity Verification card and the DoD common access card.

A privileged account is any information system account with authorizations of a privileged user. 

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to use DoD PKI or another form of multifactor authentication for network access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access.

If the Central Log Server is not configured to use multifactor authentication for network access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access, this is a finding.'
  desc 'fix', 'This requirement applies to all privileged user accounts used for network logon to the application.

Configure the Central Log Server to use DoD PKI or another form of multifactor authentication for network access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-81015r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81315'
  tag rid: 'SV-96029r1_rule'
  tag stig_id: 'SRG-APP-000154-AU-002360'
  tag gtitle: 'SRG-APP-000154-AU-002360'
  tag fix_id: 'F-88097r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001936']
  tag nist: ['IA-2 (6)']
end
