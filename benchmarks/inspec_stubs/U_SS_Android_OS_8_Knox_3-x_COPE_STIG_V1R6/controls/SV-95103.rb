control 'SV-95103' do
  title 'Samsung Android 8 with Knox must implement the management setting: Install DoD root and intermediate PKI certificates on the device.'
  desc 'DoD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the root and intermediate certificates are not available, an adversary could falsely sign a certificate in such a way that it could not be detected. Providing access to the DoD root and intermediate PKI certificates greatly diminishes the risk of this attack.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device has the DoD root and intermediate PKI certificates installed. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://iase.disa.mil/pki-pke (for NIPRNet) or 
http://iase.rel.disa.smil.mil/pki-pke/function_pages/tools.html (for SIPRNet).

On the MDM console, do the following:
1. Ask the MDM Administrator to display the list of server authentication certificates in the "Android Certificate" rule. 
2. Verify the DoD root and intermediate PKI certificates are present. 

On the Samsung Android 8 with Knox device, do the following:
1. Open the device settings.
2. Select "Lock screen and security".
3. Select "Other security settings".
4. Select "View security certificates".
5. Review Certificate Authorities listed under the "System" and "User" tabs.
6. Verify the presence of the DoD root and intermediate certificates.

If the MDM console "Android Certificate" does not have the DoD root and intermediate PKI certificates present or on the Samsung Android 8 with Knox device, "View security certificates" does not have the DoD root and intermediate PKI certificates present, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to install DoD root and intermediate certificates.

On the MDM console, add the PEM encoded representations of the DoD root and intermediate certificates to the certificate whitelist in the "Android Certificate" rule.

The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://iase.disa.mil/pki-pke (for NIPRNet) or 
http://iase.rel.disa.smil.mil/pki-pke/function_pages/tools.html (for SIPRNet).'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80071r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80399'
  tag rid: 'SV-95103r1_rule'
  tag stig_id: 'KNOX-08-019400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87205r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
