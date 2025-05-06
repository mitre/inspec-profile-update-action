control 'SV-224932' do
  title 'AutoPlay must be turned off for non-volume devices.'
  desc 'Allowing AutoPlay to execute may introduce malicious code to a system. AutoPlay begins reading from a drive as soon as media is inserted into the drive. As a result, the setup file of programs or music on audio media may start. This setting will disable AutoPlay for non-volume devices, such as Media Transfer Protocol (MTP) devices.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoAutoplayfornonVolume

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Disallow Autoplay for non-volume devices" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26623r465698_chk'
  tag severity: 'high'
  tag gid: 'V-224932'
  tag rid: 'SV-224932r569186_rule'
  tag stig_id: 'WN16-CC-000250'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-26611r465699_fix'
  tag 'documentable'
  tag legacy: ['SV-88209', 'V-73545']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
