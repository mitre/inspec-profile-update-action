control 'SV-253284' do
  title 'Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications. Structured Exception Handling Overwrite Protection (SEHOP) blocks exploits that use the Structured Exception Handling overwrite technique, a common buffer overflow attack.'
  desc 'check', 'Verify SEHOP is turned on.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\\

Value Name: DisableExceptionChainValidation

Value Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "Enable Structured Exception Handling Overwrite Protection (SEHOP)" to "Enabled".

This policy setting requires the installation of the SecGuide custom templates included with the STIG package. "SecGuide.admx" and "SecGuide.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56737r828934_chk'
  tag severity: 'high'
  tag gid: 'V-253284'
  tag rid: 'SV-253284r828936_rule'
  tag stig_id: 'WN11-00-000150'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-56687r828935_fix'
  tag 'documentable'
  tag cci: ['CCI-002794']
  tag nist: ['IR-8 a']
end
