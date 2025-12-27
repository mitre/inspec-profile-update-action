control 'SV-230132' do
  title 'Motorola Android Pie must have the DoD root and intermediate PKI certificates installed.'
  desc 'DoD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the root and intermediate certificates are not available, an adversary could falsely sign a certificate in such a way that it could not be detected. Providing access to the DoD root and intermediate PKI certificates greatly diminishes the risk of this attack.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that the DoD root and intermediate PKI certificates are installed. 
 
This procedure is performed on both the MDM Administration console and the Motorola Android Pie device. 
 
The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://cyber.mil/pki-pke (for NIPRNet). 
 
On the MDM console, verify that the DoD root and intermediate certificates are part of a device and/or work profile that is being pushed down to the devices.
 
On the Android Pie device: 
1. Open Settings. 
2. Tap "Security & Location". 
3. Tap on "Advanced".
4. Tap on "Encryption & credentials".
5. Tap on "Trusted credentials".
6. Verify that DoD root and intermediate PKI certificates are listed under the user tab.
 
If on the MDM console the DoD root and intermediate certificates are not listed in a profile, or the Motorola Android Pie device does not list the DoD root and intermediate certificates under the user tab, this is a finding.'
  desc 'fix', 'Configure Motorola Android Pie to install DoD root and intermediate certificates. 
 
On the MDM console, upload DoD root and intermediate certificates as part of a device and/or work profile.
 
The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://cyber.mil/pki-pke (for NIPRNet).'
  impact 0.5
  ref 'DPMS Target Motorola Android 9.x COBO STIG'
  tag check_id: 'C-58137r859760_chk'
  tag severity: 'medium'
  tag gid: 'V-230132'
  tag rid: 'SV-230132r859762_rule'
  tag stig_id: 'MOTO-09-009000'
  tag gtitle: 'GOOG-09-009000'
  tag fix_id: 'F-58086r859761_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
