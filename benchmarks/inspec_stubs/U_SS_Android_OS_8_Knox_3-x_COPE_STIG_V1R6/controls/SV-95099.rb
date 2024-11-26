control 'SV-95099' do
  title 'Samsung Android 8 with Knox must implement the management setting: Enable Certificate Revocation Status (CRL) Check.'
  desc 'A CRL allows a certificate issuer to revoke a certificate for any reason, including improperly issued certificates and compromise of the private keys. Checking the revocation status of the certificate mitigates the risk associated with using a compromised certificate.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is configured to enable a Certificate Revocation Status (CRL) Check. 

This validation procedure is performed on the MDM Administration Console only.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the package list in the "Certificate Revocation Check (CRL)" settings in the "Android Certificate" rule.
2. Verify the string is "*" (asterisk).
3. Ask the MDM Administrator to display the enable check box in the "Certificate Revocation Check (CRL)" settings in the "Android Certificate" rule. 
4. Verify the check box is selected.

If the MDM console "Certificate Revocation Check (CRL)" settings are not enabled for all packages, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enable a Certificate Revocation Status (CRL) Check.

On the MDM console, do the following:
1. Enter the string "*" (asterisk) in the package list in the "Certificate Revocation Check (CRL)" settings in the "Android Certificate" rule.
2. Select the enable check box in the "Certificate Revocation Check (CRL)" settings in the "Android Certificate" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80067r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80395'
  tag rid: 'SV-95099r1_rule'
  tag stig_id: 'KNOX-08-019100'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87201r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
