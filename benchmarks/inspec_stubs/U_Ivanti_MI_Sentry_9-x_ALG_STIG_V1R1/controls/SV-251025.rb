control 'SV-251025' do
  title 'The Sentry providing mobile device authentication intermediary services must use multifactor authentication for network access to non-privileged accounts.'
  desc 'To ensure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication uses two or more factors to achieve authentication. Factors include: 

1. Something you know (e.g., password/PIN)
2. Something you have (e.g., cryptographic, identification device, token) 
3. Something you are (e.g., biometric)

Non-privileged accounts are not authorized access to the network element regardless of access method.

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

Authenticating with a PKI credential and entering the associated PIN is an example of multifactor authentication.

This requirement applies to ALGs that provide user authentication intermediary services.'
  desc 'check', 'Verify the MobileIron Core has a device-level password policy enforcing password or biometric and is applied to managed devices. This should be done by default.

Verify the Sentry is configured for certificate based authentication.

Verify the Sentry is set up to provide user authentication intermediary services.

1. In the MobileIron Core Portal, select Services >> Sentry.
2. Click the "Edit" icon for the Standalone Sentry entry.
3. In the "Device Authentication Configuration" section, select an option appropriate for this implementation.
4. Depending on the option selected, follow the instructions in one of the following sections to complete the
configuration:
- Group Certificate
- Identity Certificate
- Identity Certificate with Kerberos constrained delegation

If Sentry is not configured for certificate-based authentication, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure the Sentry to use multifactor authentication for network access to non-privileged accounts.

1. In the MobileIron Core Portal, select Services >> Sentry.
2. Click the "Edit" icon for the Standalone Sentry entry.
3. In the "Device Authentication Configuration" section, select an option appropriate for this implementation.
4. Depending on the option selected, follow the instructions in one of the following sections to complete the configuration:
- Group Certificate
Refer to "Configuring authentication using a group certificate" for next steps.
- Identity Certificate
Refer to "Configuring authentication using an identity certificate and Pass Through" for next steps.
OR
Refer to "Configuring authentication using an identity certificate and Kerberos constrained delegation" for next steps.

For more information, in the "MobileIron Sentry 9.8.0 Guide for Core" refer to the section "Device and Server Authentication", which includes the subsection "Configuring device and server authentication".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54460r802295_chk'
  tag severity: 'medium'
  tag gid: 'V-251025'
  tag rid: 'SV-251025r802297_rule'
  tag stig_id: 'MOIS-AL-000400'
  tag gtitle: 'SRG-NET-000140-ALG-000094'
  tag fix_id: 'F-54414r802296_fix'
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
