control 'SV-217690' do
  title 'Samsung Android must be configured to enable Certificate Revocation List (CRL) status checking.'
  desc 'A CRL allows a certificate issuer to revoke a certificate for any reason, including improperly issued certificates and compromise of the private keys. Checking the revocation status of the certificate mitigates the risk associated with using a compromised certificate.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that CRL checking is enabled for all apps. 
 
This procedure is performed on the MDM Administration console only. 
 
On the MDM console, for the device, in the "Knox certificate" group, verify that "revocation check" is configured to "enable for all apps". 
 
If on the MDM console "revocation check" is not configured to "enable for all apps", this is a finding.'
  desc 'fix', 'Configure Samsung Android to enable CRL checking for all apps. 

On the MDM console, for the device, in the "Knox certificate" group, configure "revocation check" to "enable for all apps". 

Refer to the MDM documentation to determine how to configure revocation checking to "enable for all apps". Some may, for example, allow a wildcard string: "*" (asterisk).'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE AE'
  tag check_id: 'C-18909r362099_chk'
  tag severity: 'medium'
  tag gid: 'V-217690'
  tag rid: 'SV-217690r388482_rule'
  tag stig_id: 'KNOX-09-001050'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-18907r362100_fix'
  tag 'documentable'
  tag legacy: ['SV-103005', 'V-92917']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
