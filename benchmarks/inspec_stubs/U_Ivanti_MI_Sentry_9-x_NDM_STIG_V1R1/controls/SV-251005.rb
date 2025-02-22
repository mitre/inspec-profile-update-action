control 'SV-251005' do
  title 'MobileIron Sentry must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Determine if the MobileIron Sentry has a public certificate from an approved Certificate Authority. 

From MobileIron Core:
1. Log in to the MobileIron Core.
2. Navigate to "Services".
3. Select "Sentry".
4. On each configured Sentry, select "View Certificate".
5. Validate the Public Key is issued from an approved Certificate Authority.

From MobileIron Sentry:
1. Log in to the MobileIron Sentry. 
2. Navigate to "Security".
3. Scroll down to "Certificate Mgmt".
4. Select "View Certificate".

If approved certificates have not been uploaded, this is a finding.'
  desc 'fix', 'Configure the MobileIron Sentry with a certificate from an approved Certificate Authority.

From MobileIron Core:
1. Log in to the MobileIron Core.
2. Navigate to "Services".
3. Select "Sentry".
4. On each configured Sentry, select "Manage Certificate".
5. Upload appropriate certificate. 

From MobileIron Sentry:
1. Log in to the MobileIron Sentry. 
2. Navigate to "Security".
3. Select "Certificate Management".
4. Select "Manage Certificate".
5. Upload appropriate certificate. 

Reference "MobileIron Sentry Guide for MobileIron Core" for uploading a certificate to MobileIron Sentry, section "Standalone Sentry Certificate".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54440r802235_chk'
  tag severity: 'medium'
  tag gid: 'V-251005'
  tag rid: 'SV-251005r802237_rule'
  tag stig_id: 'MOIS-ND-000970'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-54394r802236_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
