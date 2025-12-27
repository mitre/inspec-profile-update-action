control 'SV-241231' do
  title 'Samsung Android Work Environment must have the DoD root and intermediate PKI certificates installed.'
  desc 'DoD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the root and intermediate certificates are not available, an adversary could falsely sign a certificate in such a way that it could not be detected. Providing access to the DoD root and intermediate PKI certificates greatly diminishes the risk of this attack.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android Work Environment configuration settings to determine if the DoD root and intermediate PKI certificates are installed.

Confirm if Method #1 or #2 is used at the Samsung device site and follow the appropriate procedure.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://cyber.mil/pki-pke (for NIPRNet).

****

Method #1: Use AE Key management.

On the management tool, in the Work Environment certificate section, verify that the DoD root and intermediate PKI certificates are installed.

On the Samsung Android device, do the following:
1. Open Settings >> Biometrics and security >> Other security settings >> View security certificates.
2. In the User tab, verify that the DoD root and intermediate PKI certificates are listed in the Work Environment.

If on the management tool the DoD root and intermediate PKI certificates are not listed in the Work Environment, or on the Samsung Android device the DoD root and intermediate PKI certificates are not listed in the Work Environment, this is a finding.

****

Method #2: Use KPE Key management.

On the management tool, in the Work Environment KPE certificate section, verify that the DoD root and intermediate PKI certificates are installed.

On the Samsung Android device, do the following:
1. Open Settings >> Biometrics and security >> Other security settings >> View security certificates.
2. In the User tab, verify that the DoD root and intermediate PKI certificates are listed in the Work Environment.

If on the management tool the DoD root and intermediate PKI certificates are not listed in the Work Environment, or on the Samsung Android device the DoD root and intermediate PKI certificates are not listed in the Work Environment, this is a finding.'
  desc 'fix', 'Configure the Samsung Android Work Environment to install DoD root and intermediate PKI certificates.

Do one of the following:
- Method #1: Use AE Key management.
- Method #2: Use KPE Key management.

The current DoD root and intermediate PKI certificates may be obtained in self-extracting zip files at http://cyber.mil/pki-pke (for NIPRNet).

****

Method #1: Use AE Key management.

On the management tool, in the Work Environment certificate section, install the DoD root and intermediate PKI certificates.

****

Method #2: Use KPE Key management.

On the management tool, in the Work Environment KPE certificate section, install the DoD root and intermediate PKI certificates.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44507r680332_chk'
  tag severity: 'medium'
  tag gid: 'V-241231'
  tag rid: 'SV-241231r680334_rule'
  tag stig_id: 'KNOX-10-012300'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-44466r680333_fix'
  tag 'documentable'
  tag legacy: ['SV-109095', 'V-99991']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
