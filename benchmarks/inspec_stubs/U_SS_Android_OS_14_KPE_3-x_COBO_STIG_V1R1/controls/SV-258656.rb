control 'SV-258656' do
  title 'The Samsung Android device must be configured to enable Certificate Revocation List (CRL) status checking.'
  desc 'A CRL allows a certificate issuer to revoke a certificate for any reason, including improperly issued certificates and compromise of the private keys. Checking the revocation status of the certificate mitigates the risk associated with using a compromised certificate. For this reason, users must not be able to disable this configuration.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the configuration to confirm that revocation checking is enabled. Verify the revocation checklist is set to "All Applications".
 
This procedure is performed on the management tool. 

On the management tool:
1. Open "Certificates Policy >> Revocation" section.
2. Select "Get CRL".
3. Verify Toast message "Get revocation check: true".

If on the management tool the revocation check is disabled, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to enable CRL revocation checks for all applications.

On the management tool, in the Certificate Policy restrictions, enable "Revocation Checks" for "All Applications".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COBO'
  tag check_id: 'C-62396r931166_chk'
  tag severity: 'medium'
  tag gid: 'V-258656'
  tag rid: 'SV-258656r931168_rule'
  tag stig_id: 'KNOX-14-125010'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62305r931167_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
