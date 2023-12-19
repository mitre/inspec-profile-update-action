control 'SV-255161' do
  title "Samsung Android's Work profile must allow only the Administrator (management tool) to perform the following management function: Install/remove DOD root and intermediate PKI certificates."
  desc 'DOD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the user is allowed to remove root and intermediate certificates, the user could allow an adversary to falsely sign a certificate in such a way that it could not be detected. Restricting the ability to remove DOD root and intermediate PKI certificates to the Administrator mitigates this risk.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', %q(Review the configuration to determine if the Samsung Android devices' Work profile is preventing users from removing DOD root and intermediate PKI certificates.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the Work profile restrictions, verify that "Configure credentials" is set to "Disallow".

On the Samsung Android device: 
1. Open Settings >> Security and privacy >> Other security settings >> View security certificates.
2. In the System tab, verify that no listed certificate in the Work profile can be untrusted.
3. In the User tab, verify that no listed certificate in the Work profile can be removed.

If on the management tool the device "Configure credentials" is not set to "Disallow", or on the Samsung Android device a certificate can be untrusted or removed, this is a finding.)
  desc 'fix', %q(Configure the Samsung Android devices' Work profile to prevent users from removing DOD root and intermediate PKI certificates.

On the management tool, in the Work profile restrictions, set "Configure credentials" to "Disallow".)
  impact 0.5
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COPE'
  tag check_id: 'C-58774r867418_chk'
  tag severity: 'medium'
  tag gid: 'V-255161'
  tag rid: 'SV-255161r867420_rule'
  tag stig_id: 'KNOX-13-210260'
  tag gtitle: 'PP-MDF-323350'
  tag fix_id: 'F-58718r867419_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
