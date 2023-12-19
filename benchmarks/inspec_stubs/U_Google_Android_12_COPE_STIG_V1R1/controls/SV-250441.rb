control 'SV-250441' do
  title 'Google Android 12 must have the DoD root and intermediate PKI certificates installed.'
  desc 'DoD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the root and intermediate certificates are not available, an adversary could falsely sign a certificate in such a way that it could not be detected. Providing access to the DoD root and intermediate PKI certificates greatly diminishes the risk of this attack.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that the DoD root and intermediate PKI certificates are installed.
 
This procedure is performed on both the EMM Administration console and the managed Google Android 12 device. 
 
The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://cyber.mil/pki-pke (for NIPRNet). 
 
On the EMM console verify that the DoD root and intermediate certificates are part of a device and/or work profile that is being pushed down to the devices.
 
On the managed Google Android 12 device: 

1. Open Settings. 
2. Tap "Security". 
3. Tap "Advanced".
4. Tap "Encryption & credentials".
5. Tap "Trusted credentials".
6. Verify that DoD root and intermediate PKI certificates are listed under the User tab in the Work section.
 
If on the EMM console the DoD root and intermediate certificates are not listed in a profile, or the managed Android 12 device does not list the DoD root and intermediate certificates under the user tab, this is a finding.'
  desc 'fix', 'Configure the Google Android 12 device to install DoD root and intermediate certificates. 
 
On the EMM console upload DoD root and intermediate certificates as part of a device and/or work profile.
 
The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://cyber.mil/pki-pke (for NIPRNet).'
  impact 0.5
  ref 'DPMS Target Google Android 12 COPE'
  tag check_id: 'C-53876r796829_chk'
  tag severity: 'medium'
  tag gid: 'V-250441'
  tag rid: 'SV-250441r802681_rule'
  tag stig_id: 'GOOG-12-010000'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-53830r796830_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
