control 'SV-91197' do
  title 'The Akamai Luna Portal must employ Security Assertion Markup Language (SAML) to automate central management of administrators.'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion.'
  desc 'check', 'Confirm that only SAML logins are enabled.

1. Log in to the Akamai Luna Portal (Caution-https://control.akamai.com).
2. Click "Configure" >> "Manage SSO with SAML"
3. Verify "SAML-only login:" is set to "enabled"

If the "SAML only logins:" is set to disabled, this is a finding.

NOTE: During the initial deployment and testing of the Luna Portal implementation, it will be necessary to allow other logins. However, production environments must meet this requirement.'
  desc 'fix', 'Configure logins to require SAML integration.

1. Log in to the Akamai Luna Portal (Caution-https://control.akamai.com).
2. Click "Configure" >> "Manage SSO with SAML"
3. Click the "Enable" button next to the "SAML-only login:" label.
4. Click "Yes" when asked if you want to enable SAML-only login.'
  impact 0.7
  ref 'DPMS Target Akamai Edge Security NDM'
  tag check_id: 'C-76161r1_chk'
  tag severity: 'high'
  tag gid: 'V-76501'
  tag rid: 'SV-91197r1_rule'
  tag stig_id: 'AKSD-DM-000117'
  tag gtitle: 'SRG-APP-000516-NDM-000337'
  tag fix_id: 'F-83179r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000371']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
