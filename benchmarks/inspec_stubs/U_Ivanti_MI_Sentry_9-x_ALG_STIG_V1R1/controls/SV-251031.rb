control 'SV-251031' do
  title 'The Sentry providing mobile device authentication intermediary services must implement multifactor authentication for remote access to non-privileged accounts such that one of the factors is provided by a device separate from the system gaining access.'
  desc 'For remote access to non-privileged accounts, the purpose of requiring a device that is separate from the information system gaining access for one of the factors during multifactor authentication is to reduce the likelihood of compromising authentication credentials stored on the system.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD common access card.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

An example of compliance with this requirement is the use of a one-time password token and PIN coupled with a password; or the use of a CAC/PIV card and PIN coupled with a password.'
  desc 'check', 'If the Sentry does not provide user authentication intermediary services, this is not applicable.

Verify the Sentry implements multifactor authentication for remote access to non-privileged accounts.

Verify the MobileIron Core has a device-level password policy enforcing password or biometric and is applied to managed devices. This should be done by default.

Verify the Sentry is configured for certificate-based authentication.

If the Sentry is set up as an intermediary service for backend resources:
1. In the MobileIron Core Portal, select Services >> Sentry.
2. Click the "Edit" icon for the Standalone Sentry entry.
3. In the "Device Authentication Configuration" section, select an option appropriate for this implementation.
4. Depending on the option selected, follow the instructions in one of the following sections to verify the configuration is correct:
- Group Certificate
- Identity Certificate
- Identity Certificate with Kerberos constrained delegation

If the "Device Authentication Configuration" is not set up correctly, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure the Sentry to implement multifactor authentication for remote access to non-privileged accounts such that one of the factors is provided by a device separate from the system gaining access.

1. In the MobileIron Core Portal, select Services >> Sentry.
2. Click the "Edit" icon for the Standalone Sentry entry.
3. In the "Device Authentication Configuration" section, select an option appropriate for this implementation.
4. Depending on the option selected, follow the instructions in one of the following section to complete the configuration:
- Group Certificate
Refer to "Configuring authentication using a group certificate" for next steps.
- Identity Certificate
Refer to "Configuring authentication using an identity certificate and Pass Through" for next steps.
OR
Refer to "Configuring authentication using an identity certificate and Kerberos constrained delegation" for next steps.

For more information, in the "MobileIron Sentry 9.8.0 Guide for Core", refer to the main section "Device and Server Authentication", which contains the subsection "Configuring device and server authentication".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54466r802313_chk'
  tag severity: 'medium'
  tag gid: 'V-251031'
  tag rid: 'SV-251031r802315_rule'
  tag stig_id: 'MOIS-AL-000900'
  tag gtitle: 'SRG-NET-000339-ALG-000090'
  tag fix_id: 'F-54420r802314_fix'
  tag 'documentable'
  tag cci: ['CCI-001951']
  tag nist: ['IA-2 (11)']
end
