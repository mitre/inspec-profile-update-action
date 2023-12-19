control 'SV-251013' do
  title 'The Sentry that provides intermediary services for TLS must be configured to comply with the required TLS settings in NIST SP 800-52.'
  desc 'SP 800-52 provides guidance on using the most secure version and configuration of the TLS/SSL protocol. Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks which exploit vulnerabilities in this protocol.'
  desc 'check', 'Verify the Sentry is configured to implement the applicable required TLS settings in NIST PUB SP 800-52.

1. Log in to MobileIron Sentry.
2. Go to Settings >> Services >> Sentry.
3. For each of the following configurations, follow the step 4 procedure: 
     a. Incoming SSL configuration
     b. Outgoing SSL configuration
     c. UEM SSL configuration
     d. Access SSL configuration
4. Verify only TLS 1.2 is selected.

If any other protocol is selected, this is a finding.

For more information, go to the "MobileIron Sentry 9.8.0 guide for Core" and refer the main section "Standalone Sentry Settings", which includes subsections on how TLS 1.2 is set as the default protocol: 
1. Incoming SSL configuration
2. Outgoing SSL configuration
3. UEM SSL configuration
4. Access SSL configuration

MobileIron Sentry conforms to the NIST SP 800-52 TLS settings by setting TLS 1.2 by default.'
  desc 'fix', 'Configure the Sentry to comply with applicable required TLS settings in NIST PUB SP 800-52.

1. Log in to MobileIron Sentry.
2. Go to Settings >> Services >> Sentry.
3. For each of the following configurations, follow the step 4 procedure: 
     a. Incoming SSL configuration
     b. Outgoing SSL configuration
     c. UEM SSL configuration
     d. Access SSL configuration
4. Select only TLS 1.2 and remove others if selected.
5. Click "Apply".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54448r802259_chk'
  tag severity: 'medium'
  tag gid: 'V-251013'
  tag rid: 'SV-251013r802261_rule'
  tag stig_id: 'MOIS-AL-000180'
  tag gtitle: 'SRG-NET-000062-ALG-000150'
  tag fix_id: 'F-54402r802260_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
