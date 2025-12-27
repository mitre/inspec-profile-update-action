control 'SV-251820' do
  title 'Samsung Android must have the DoD root and intermediate PKI certificates installed.'
  desc 'DoD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the root and intermediate certificates are not available, an adversary could falsely sign a certificate in such a way that it could not be detected. Providing access to the DoD root and intermediate PKI certificates greatly diminishes the risk of this attack.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices have the DoD root and intermediate PKI certificates installed.

This validation procedure is performed on both the management tool and the Samsung Android device.

The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at https://cyber.mil/pki-pke (for NIPRNet).

On the management tool, in the device policy management, verify that the DoD root and intermediate PKI certificates are installed.

On the Samsung Android device: 
1. Open Settings >> Biometrics and security >> Other security settings >> View security certificates.
2. In the User tab, verify that the DoD root and intermediate PKI certificates are listed in the Device.

If on the management tool the DoD root and intermediate PKI certificates are not listed in the Device, or on the Samsung Android device the DoD root and intermediate PKI certificates are not listed in the Device, this is a finding.'
  desc 'fix', 'Install the DoD root and intermediate PKI certificates into the Samsung Android devices.

The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at https://cyber.mil/pki-pke (for NIPRNet).

On the management tool, in the device policy management, install the DoD root and intermediate PKI certificates.'
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COBO'
  tag check_id: 'C-55280r814214_chk'
  tag severity: 'medium'
  tag gid: 'V-251820'
  tag rid: 'SV-251820r814216_rule'
  tag stig_id: 'KNOX-12-110180'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-55234r814215_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
