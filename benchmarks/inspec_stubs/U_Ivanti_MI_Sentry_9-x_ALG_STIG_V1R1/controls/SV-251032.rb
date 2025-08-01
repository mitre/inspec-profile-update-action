control 'SV-251032' do
  title 'The Sentry providing mobile device authentication intermediary services using PKI-based mobile device authentication must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of protected sessions.'
  desc 'Non-DoD-approved PKIs have not been evaluated to ensure they have security controls and identity vetting procedures in place that are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.

The authoritative list of DoD-approved PKIs is published at https://cyber.mil/pki-pke/interoperability. DoD-approved PKI CAs may include Category I, II, and III certificates. Category I DoD-approved External PKIs are PIV issuers. Category II DoD-approved External PKIs are Non-Federal Agency PKIs cross-certified with the Federal Bridge Certification Authority (FBCA). Category III DoD-approved External PKIs are Foreign, Allied, or Coalition Partner PKIs.

Deploying the ALG with TLS enabled will require the installation of DoD and/or DoD-approved CA certificates in the trusted root certificate store of each proxy to be used for TLS traffic. 

This requirement focuses on communications protection for the application session rather than for the network packet.'
  desc 'check', 'Verify Sentry only accepts end entity certificates issued by DoD PKI or DoD-approved PKI CAs for the establishment of protected sessions.

Verify the MobileIron Core has a device-level password policy enforcing password or biometric and is applied to managed devices. This should be done by default.

Verify the Sentry is configured for certificate-based authentication:

Verify the Sentry is set up to provide user authentication intermediary services:
1. In the MobileIron Core Portal, select Services >> Sentry.
2. Click the "Edit" icon for the Standalone Sentry entry.
3. In the "Device Authentication Configuration" section, select an option appropriate for this implementation.
4. Depending on the option selected, follow the instructions in one of the following sections to complete the configuration:
- Group Certificate
- Identity Certificate
- Identity Certificate with Kerberos constrained delegation 
5. Select "View Certificate" and verify DoD and/or DoD-approved CA certificates are presented.

If non-DoD-approved certificates are used, this is a finding.'
  desc 'fix', 'If PKI-based user authentication intermediary services are provided, configure Sentry to only accept end entity certificates issued by DoD PKI or DoD-approved PKI CAs for the establishment of protected sessions.

1. In the MobileIron Core Portal, select Services >> Sentry.
2. Click the "Edit" icon for the Standalone Sentry entry.
3. In the "Device Authentication Configuration" section, select an option appropriate for your implementation.
4. Depending on the option selected, follow the instructions in one of the following sections to complete the configuration: 
- Group Certificate 
Refer to "Configuring authentication using a group certificate" for next steps.
- Identity Certificate
Refer to "Configuring authentication using an identity certificate and Pass Through" for next steps.
OR 
Refer to "Configuring authentication using an identity certificate and Kerberos constrained delegation" for next steps. 

For more information, in the "MobileIron Sentry 9.8.0 Guide for Core", refer to the main section "Device and Server Authentication", which contains the subsection "Configuring device and server authentication".

5. From the "Upload Certificate" option, load the DoD and/or DoD-approved CA certificates.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54467r802316_chk'
  tag severity: 'medium'
  tag gid: 'V-251032'
  tag rid: 'SV-251032r802318_rule'
  tag stig_id: 'MOIS-AL-000950'
  tag gtitle: 'SRG-NET-000355-ALG-000117'
  tag fix_id: 'F-54421r802317_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
