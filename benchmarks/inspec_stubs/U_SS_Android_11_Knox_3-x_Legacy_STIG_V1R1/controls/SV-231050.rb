control 'SV-231050' do
  title 'Samsung Android Work Environment must have the DoD root and intermediate PKI certificates installed.'
  desc 'DoD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the root and intermediate certificates are not available, an adversary could falsely sign a certificate in such a way that it could not be detected. Providing access to the DoD root and intermediate PKI certificates greatly diminishes the risk of this attack.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android Work Environment configuration settings to determine if the DoD root and intermediate PKI certificates are installed.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at https://cyber.mil/pki-pke (for NIPRNet).

On the management tool, in the Work Environment certificate section, verify that the DoD root and intermediate PKI certificates are installed.

On the Samsung Android device: 
1. Open Settings >> Biometrics and security >> Other security settings >> View security certificates.
2. In the User tab, verify that the DoD root and intermediate PKI certificates are listed in the Work Environment.

If on the management tool the DoD root and intermediate PKI certificates are not listed in the Work Environment, or on the Samsung Android device the DoD root and intermediate PKI certificates are not listed in the Work Environment, this is a finding.'
  desc 'fix', 'Configure the Samsung Android Work Environment to install DoD root and intermediate PKI certificates.

The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at https://cyber.mil/pki-pke (for NIPRNet).

On the management tool, in the Work Environment certificate section, install the DoD root and intermediate PKI certificates.'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33980r592764_chk'
  tag severity: 'medium'
  tag gid: 'V-231050'
  tag rid: 'SV-231050r608683_rule'
  tag stig_id: 'KNOX-11-023000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-33953r592765_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
