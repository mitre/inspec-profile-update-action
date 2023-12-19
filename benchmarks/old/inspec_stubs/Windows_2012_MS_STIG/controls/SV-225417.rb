control 'SV-225417' do
  title 'Systems must be maintained at a supported OS or service pack level.'
  desc 'Systems at unsupported service packs or releases will not receive security updates for new vulnerabilities, which leave them subject to exploitation. Systems must be maintained at a service pack level supported by the vendor with new security updates.'
  desc 'check', 'Run "winver.exe".

If the "About Windows" displays the following or less, this is a finding:
"Microsoft Windows Server 
Version 6.3 (Build 9600)"
 
Windows Server 2012 and 2012 R2 support ended on October 10, 2023.

If Extended Security Updates (ESUs up to three years) have not been acquired, this is a finding.'
  desc 'fix', 'Update the system to a supported release or operating system.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27116r921959_chk'
  tag severity: 'high'
  tag gid: 'V-225417'
  tag rid: 'SV-225417r921961_rule'
  tag stig_id: 'WN12-GE-000001'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-27104r921960_fix'
  tag 'documentable'
  tag legacy: ['SV-53189', 'V-1073']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
