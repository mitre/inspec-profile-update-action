control 'SV-251028' do
  title 'The Sentry providing PKI-based mobile device authentication intermediary services must map authenticated identities to the mobile device account.'
  desc 'Authorization for access to any network element requires an approved and assigned individual account identifier. To ensure only the assigned individual is using the account, the account must be bound to a user certificate when PKI-based authentication is implemented.

This requirement applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).'
  desc 'check', 'Verify the Sentry is configured with certificate-based authentication with the appropriate certificate field user mappings.
 
1. In the MobileIron Core Portal, select Services >> Sentry.
2. Click the "Edit" icon for the Standalone Sentry entry.
3. In the "Device Authentication Configuration" section, verify certificate mappings are configured in the "certificate mapping" field.

If Sentry is not configured to map authenticated identities to the user accounts, this is a finding.'
  desc 'fix', 'If PKI-based user authentication intermediary services are provided, configure the Sentry to map the authenticated identities to the user account.

1. In the MobileIron Core Portal, select Services >> Sentry.
2. Click the "Edit" icon the Standalone Sentry entry.
3. In the "Device Authentication Configuration" section, configure certificate mappings in the "certificate mapping" field (i.e., User UPN = Subject Alternative Name: NT Principal Name).
4. Click "Save".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54463r802304_chk'
  tag severity: 'medium'
  tag gid: 'V-251028'
  tag rid: 'SV-251028r802306_rule'
  tag stig_id: 'MOIS-AL-000430'
  tag gtitle: 'SRG-NET-000166-ALG-000101'
  tag fix_id: 'F-54417r802305_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
