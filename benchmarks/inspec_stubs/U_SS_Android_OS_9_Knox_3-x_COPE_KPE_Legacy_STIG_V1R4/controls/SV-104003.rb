control 'SV-104003' do
  title 'Samsung Android Workspace must have the DoD root and intermediate PKI certificates installed.'
  desc 'DoD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the root and intermediate certificates are not available, an adversary could falsely sign a certificate in such a way that it could not be detected. Providing access to the DoD root and intermediate PKI certificates greatly diminishes the risk of this attack.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review the Samsung Android Workspace configuration settings to confirm that the DoD root and intermediate PKI certificates are installed.

This procedure is performed on both the MDM Administration console and the Samsung Android device.

The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://iase.disa.mil/pki-pke (for NIPRNet). 

On the MDM console, for the Workspace, in the "Knox certificate" group, verify that the DoD root and intermediate PKI certificates are listed.

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Biometrics and security". 
3. Tap "Other security settings". 
4. Tap "View security certificates". 
5. Verify the DoD root and intermediate certificates are listed under the "Work" list in the "User" tab.

If on the MDM console the DoD root and intermediate certificates are not listed in the "Knox certificate" group, or on the Samsung Android device "View security certificates" does not list the DoD root and intermediate certificates, this is a finding.'
  desc 'fix', 'Configure Samsung Android Workspace to install DoD root and intermediate certificates. 

On the MDM console, for the Workspace, in the "Knox certificate" group, use "install a CA certificate" to install the DoD root and intermediate certificates. 

The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://iase.disa.mil/pki-pke (for NIPRNet) or 
http://iase.rel.disa.smil.mil/pki-pke/function_pages/tools.html (for SIPRNet).'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COPE KPE(Legacy)'
  tag check_id: 'C-93235r3_chk'
  tag severity: 'medium'
  tag gid: 'V-93917'
  tag rid: 'SV-104003r2_rule'
  tag stig_id: 'KNOX-09-001075'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-100165r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
