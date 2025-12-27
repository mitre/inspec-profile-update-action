control 'SV-228300' do
  title 'Google Android Pie must have the DoD root and intermediate PKI certificates installed.'
  desc 'DoD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the root and intermediate certificates are not available, an adversary could falsely sign a certificate in such a way that it could not be detected. Providing access to the DoD root and intermediate PKI certificates greatly diminishes the risk of this attack.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that the DoD root and intermediate PKI certificates are installed. 

This procedure is performed on both the MDM Administration console and the Google Android Pie device. 

The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://cyber.mil/pki-pke (for NIPRNet). 

On the MDM console verify that the DoD root and intermediate certificates are part of a device and/or work profile that is being pushed down to the devices.

On the Google Android Pie device, do the following: 
1. Open Settings. 
2. Tap "Security & Location". 
3. Tap on "Advanced".
4. Tap on "Encryption & credentials".
5. Tap on "Trusted credentials".
6. Verify that DoD root and intermediate PKI certificates are listed under the user tab.

If on the MDM console the DoD root and intermediate certificates are not listed in a profile, or on the Google Android Pie device does not list the DoD root and intermediate certificates under the user tab, this is a finding.'
  desc 'fix', 'Configure Google Android Pie to install DoD root and intermediate certificates. 

On the MDM console upload DoD root and intermediate certificates as part of a device and/or work profile

The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://cyber.mil/pki-pke (for NIPRNet).'
  impact 0.5
  ref 'DPMS Target Google Android 9-x'
  tag check_id: 'C-30533r494967_chk'
  tag severity: 'medium'
  tag gid: 'V-228300'
  tag rid: 'SV-228300r494969_rule'
  tag stig_id: 'GOOG-09-009000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-30518r494968_fix'
  tag 'documentable'
  tag legacy: ['SV-106453', 'V-97349']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
