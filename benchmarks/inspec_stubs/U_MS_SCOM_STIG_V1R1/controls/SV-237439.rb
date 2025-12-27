control 'SV-237439' do
  title 'All SCOM servers must be configured for FIPS 140-2 compliance.'
  desc 'Unapproved mechanisms used for authentication to the cryptographic module are not validated and therefore cannot be relied on to provide confidentiality or integrity, and DoD data may be compromised. FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. However, authentication algorithms must configure security processes to use only FIPS-approved and NIST-recommended authentication algorithms.

SCOM is FIPS-compliant out of the box with the exception of the Web Console.'
  desc 'check', 'From a SCOM Management server, open the registry editor. Navigate to the following key:

HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy

Verify that the "Enabled" key is set to 1.

If the "Enabled" key is not set to 1 or is not present, this is a finding.

From a command prompt, open the following file with notepad: C:\\Windows\\Micosoft.NET\\Framework]v2.0.50727\\CONFIG\\machine.config. Immediately following the <ConfigSection>, look for <cryptographySettings>. 

If the <cryptographySettings> section does not exist under <ConfigSection> of the machine.config file, this is a finding.'
  desc 'fix', 'From a SCOM Management server, open the registry editor. Navigate to the following key:

HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy

Double-click on "Enabled" and set the value to 1.

Note that many organizations use a GPO to accomplish this task. Older versions of SCOM may require additional configuration. That is documented here: https://nathangau.wordpress.com/2016/12/02/scom-2012-webconsole-and-fips-compatibility/'
  impact 0.7
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40658r643961_chk'
  tag severity: 'high'
  tag gid: 'V-237439'
  tag rid: 'SV-237439r643963_rule'
  tag stig_id: 'SCOM-SC-000001'
  tag gtitle: 'SRG-APP-000224-NDM-000270'
  tag fix_id: 'F-40621r643962_fix'
  tag 'documentable'
  tag cci: ['CCI-000803', 'CCI-001188']
  tag nist: ['IA-7', 'SC-23 (3)']
end
