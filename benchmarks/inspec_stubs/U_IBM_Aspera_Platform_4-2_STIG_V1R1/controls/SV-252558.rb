control 'SV-252558' do
  title 'IBM Aspera Console must implement multifactor authentication for remote access to non-privileged accounts such that one of the factors is provided by a device separate from the system gaining access.'
  desc 'For remote access to non-privileged accounts, the purpose of requiring a device that is separate from the information system gaining access for one of the factors during multifactor authentication is to reduce the likelihood of compromising authentication credentials stored on the system.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD common access card.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

An example of compliance with this requirement is the use of a one-time password token and PIN coupled with a password; or the use of a CAC/PIV card and PIN coupled with a password.

'
  desc 'check', 'Using a web browser, navigate to the default IBM Aspera Console web page. Use the SAML link and authenticate using known working credentials.

If entry of a factor provided by a device separate from the system gaining access is NOT required, this is a finding.'
  desc 'fix', 'For implementations using the IBM Aspera Console feature, configure SAML to use an existing IdP that implements multi-factor authentication.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56014r817842_chk'
  tag severity: 'medium'
  tag gid: 'V-252558'
  tag rid: 'SV-252558r817844_rule'
  tag stig_id: 'ASP4-CS-040110'
  tag gtitle: 'SRG-NET-000339-ALG-000090'
  tag fix_id: 'F-55964r817843_fix'
  tag satisfies: ['SRG-NET-000339-ALG-000090', 'SRG-NET-000340-ALG-000091', 'SRG-NET-000349-ALG-000106']
  tag 'documentable'
  tag cci: ['CCI-001948', 'CCI-001951', 'CCI-002014']
  tag nist: ['IA-2 (11)', 'IA-2 (11)', 'IA-8 (4)']
end
