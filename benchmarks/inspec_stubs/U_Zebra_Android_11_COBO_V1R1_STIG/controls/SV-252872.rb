control 'SV-252872' do
  title 'Zebra Android 11 must have the DoD root and intermediate PKI certificates installed.'
  desc 'DoD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the root and intermediate certificates are not available, an adversary could falsely sign a certificate in such a way that it could not be detected. Providing access to the DoD root and intermediate PKI certificates greatly diminishes the risk of this attack.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that the DoD root and intermediate PKI certificates are installed.
 
This procedure is performed on both the EMM Administration console and the Zebra Android 11 device. 
 
The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://cyber.mil/pki-pke (for NIPRNet). 
 
On the EMM console verify that the DoD root and intermediate certificates are part of a device and/or work profile that is being pushed down to the devices.
 
On the Zebra Android 11 device, do the following: 
1. Open "Settings". 
2. Tap "Security". 
3. Tap "Advanced".
4. Tap "Encryption & credentials".
5. Tap "Trusted credentials".
6. Verify that DoD root and intermediate PKI certificates are listed under the User tab in the Work section.
 
If on the EMM console the DoD root and intermediate certificates are not listed in a profile, or the Zebra Android 11 device does not list the DoD root and intermediate certificates under the user tab, this is a finding.'
  desc 'fix', 'Configure Zebra Android 11 device to install DoD root and intermediate certificates. 
 
On the EMM console upload DoD root and intermediate certificates as part of a device and/or work profile.
 
The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://cyber.mil/pki-pke (for NIPRNet).'
  impact 0.5
  ref 'DPMS Target Zebra Android 11 COBO'
  tag check_id: 'C-56328r820541_chk'
  tag severity: 'medium'
  tag gid: 'V-252872'
  tag rid: 'SV-252872r820543_rule'
  tag stig_id: 'ZEBR-11-009000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-56278r820542_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
