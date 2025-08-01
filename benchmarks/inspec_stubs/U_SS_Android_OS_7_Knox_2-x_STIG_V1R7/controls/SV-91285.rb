control 'SV-91285' do
  title 'The Samsung Android 7 with Knox must implement the management setting: Enable Certificate Revocation Status (CRL) Check.'
  desc 'A CRL allows a certificate issuer to revoke a certificate for any reason, including improperly issued certificates and compromise of the private keys. Checking the revocation status of the certificate mitigates the risk associated with using a compromised certificate.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is configured to enable a Certificate Revocation Status (CRL) Check. 

This validation procedure is performed on the MDM Administration Console only.

On the MDM console, do the following:
1. Ask the MDM administrator to display the package list in the "Certificate Revocation Check (CRL)" settings in the "Android Certificate" rule.
2. Verify the string is '*' (asterisk).
3. Ask the MDM administrator to display the enable checkbox in the "Certificate Revocation Check (CRL)" settings in the "Android Certificate" rule. 
4. Verify the checkbox is selected.

If the MDM console "Certificate Revocation Check (CRL)" settings are not enabled for all packages, this is a finding.)
  desc 'fix', %q(Configure the Samsung Android 7 with Knox to enable a Certificate Revocation Status (CRL) Check.

On the MDM console, do the following:
1. Enter the string '*' (asterisk) in the package list in the "Certificate Revocation Check (CRL)" settings in the "Android Certificate" rule.
2. Select the enable checkbox in the "Certificate Revocation Check (CRL)" settings in the "Android Certificate" rule.)
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76257r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76589'
  tag rid: 'SV-91285r1_rule'
  tag stig_id: 'KNOX-07-013000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83283r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
