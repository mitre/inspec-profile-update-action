control 'SV-251027' do
  title 'The Sentry that provides intermediary services for TLS must validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. 

Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', 'The Sentry is configured with TLS by default. The Sentry enables TLS 1.2 by default. To check the status:

1. Log in to MobileIron Sentry.
2. Go to Settings >> Services >> Sentry.
3. For each of the following configurations, follow step 4:
     a. Incoming SSL configuration
     b. Outgoing SSL configuration
     c. UEM SSL configuration
     d. Access SSL configuration
4. In Protocols, verify TLS 1.2 is enabled.

If TLS 1.2 is not enabled for each configuration, this is a finding. 

For more information, go to the "MobileIron Sentry 9.8.0 Guide for Core" and refer to the main section "Standalone Sentry Settings", which includes subsections on how TLS 1.2 is set as the default protocol:
1. Incoming SSL configuration
2. Outgoing SSL configuration
3. UEM SSL configuration
4. Access SSL configuration

MobileIron Sentry conforms to the NIST SP 800-52 TLS settings by setting TLS 1.2 by default.'
  desc 'fix', 'The Sentry is configured with TLS by default. To configure the Sentry with TLS 1.2:

1. Log in to MobileIron Sentry.
2. Go to Settings >> Services >> Sentry.
3. Select each of the configurations listed below and follow steps 4 and 5:
    a. Incoming SSL configuration
    b. Outgoing SSL configuration
    c. UEM SSL Configuration
    d. Access SSL Configuration
4. In protocols, make TLS 1.2 enabled. 
5. Apply the configuration and click "Save" in the top right corner.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54462r802301_chk'
  tag severity: 'medium'
  tag gid: 'V-251027'
  tag rid: 'SV-251027r802303_rule'
  tag stig_id: 'MOIS-AL-000420'
  tag gtitle: 'SRG-NET-000164-ALG-000100'
  tag fix_id: 'F-54416r802302_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
