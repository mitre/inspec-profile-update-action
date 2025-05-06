control 'SV-237022' do
  title 'Google Android 10 must have the DoD root and intermediate PKI certificates installed.'
  desc 'DoD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the root and intermediate certificates are not available, an adversary could falsely sign a certificate in such a way that it could not be detected. Providing access to the DoD root and intermediate PKI certificates greatly diminishes the risk of this attack.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that the DoD root and intermediate PKI certificates are installed.

This procedure is performed on both the MDM Administration console and the Google Android 10 device. 

The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://cyber.mil/pki-pke (for NIPRNet). 

On the MDM console verify that the DoD root and intermediate certificates are part of a device and/or work profile that is being pushed down to the devices.

On the Google Android 10 device, do the following: 
1. Open Settings. 
2. Tap "Security". 
3. Tap "Advanced".
4. Tap "Encryption & credentials".
5. Tap "Trusted credentials".
6. Verify that DoD root and intermediate PKI certificates are listed under the User tab in the Work section.

If on the MDM console the DoD root and intermediate certificates are not listed in a profile, or the Google Android 10 device does not list the DoD root and intermediate certificates under the user tab, this is a finding.'
  desc 'fix', 'Configure Google Android 10 to install DoD root and intermediate certificates. 

On the MDM console upload DoD root and intermediate certificates as part of a device and/or work profile.

The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://cyber.mil/pki-pke (for NIPRNet).'
  impact 0.5
  ref 'DPMS Target Google Android 10-x'
  tag check_id: 'C-40241r639210_chk'
  tag severity: 'medium'
  tag gid: 'V-237022'
  tag rid: 'SV-237022r639212_rule'
  tag stig_id: 'GOOG-10-009000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-40204r639211_fix'
  tag 'documentable'
  tag legacy: ['SV-108069', 'V-98965']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
