control 'SV-255153' do
  title "Samsung Android's Work profile must have the DOD root and intermediate PKI certificates installed."
  desc 'DOD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the root and intermediate certificates are not available, an adversary could falsely sign a certificate in such a way that it could not be detected. Providing access to the DOD root and intermediate PKI certificates greatly diminishes the risk of this attack.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', "Review the configuration to determine if the Samsung Android's Work profile has the DOD root and intermediate PKI certificates installed.

This validation procedure is performed on both the management tool and the Samsung Android device.

The current DOD root and intermediate PKI certificates may be obtained in self-extracting zip files at https://cyber.mil/pki-pke (for NIPRNet).

On the management tool, in the Work profile policy management, verify that the DOD root and intermediate PKI certificates are installed.

On the Samsung Android device: 
1. Open Settings >> Security and privacy >> Other security settings >> View security certificates.
2. In the User tab, verify that the DOD root and intermediate PKI certificates are listed in the Work profile.

If on the management tool the DOD root and intermediate PKI certificates are not listed in the Work profile, or on the Samsung Android device the DOD root and intermediate PKI certificates are not listed in the Work profile, this is a finding."
  desc 'fix', "Install the DOD root and intermediate PKI certificates into the Samsung Android devices' Work profile.

The current DOD root and intermediate PKI certificates may be obtained in self-extracting zip files at https://cyber.mil/pki-pke (for NIPRNet).

On the management tool, in the Work profile policy management, install the DOD root and intermediate PKI certificates."
  impact 0.5
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COPE'
  tag check_id: 'C-58766r867394_chk'
  tag severity: 'medium'
  tag gid: 'V-255153'
  tag rid: 'SV-255153r867396_rule'
  tag stig_id: 'KNOX-13-210180'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58710r867395_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
