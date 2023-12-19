control 'SV-255191' do
  title 'Microsoft Android 11 must have the DOD root and intermediate PKI certificates installed.'
  desc 'DOD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the root and intermediate certificates are not available, an adversary could falsely sign a certificate in such a way that it could not be detected. Providing access to the DOD root and intermediate PKI certificates greatly diminishes the risk of this attack.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that the DOD root and intermediate PKI certificates are installed.
 
This procedure is performed on both the EMM Administration console and the Microsoft Android 11 device. 
 
The current DOD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://cyber.mil/pki-pke (for NIPRNet). 
 
On the EMM console verify that the DOD root and intermediate certificates are part of a device and/or work profile that is being pushed down to the devices.
 
On the Microsoft Android 11 device: 
1. Open "Settings". 
2. Tap "Security". 
3. Tap "Advanced".
4. Tap "Encryption & credentials".
5. Tap "Trusted credentials".
6. Verify that DOD root and intermediate PKI certificates are listed under the User tab in the Work section.
 
If on the EMM console the DOD root and intermediate certificates are not listed in a profile, or the Microsoft Android 11 device does not list the DOD root and intermediate certificates under the user tab, this is a finding.'
  desc 'fix', 'Configure Microsoft Android 11 device to install DOD root and intermediate certificates. 
 
On the EMM console upload DOD root and intermediate certificates as part of a device and/or work profile.
 
The current DOD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://cyber.mil/pki-pke (for NIPRNet).'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COBO'
  tag check_id: 'C-58804r870792_chk'
  tag severity: 'medium'
  tag gid: 'V-255191'
  tag rid: 'SV-255191r870793_rule'
  tag stig_id: 'MSFT-11-009000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-58748r869435_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
