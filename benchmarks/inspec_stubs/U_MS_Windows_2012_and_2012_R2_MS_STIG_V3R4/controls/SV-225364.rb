control 'SV-225364' do
  title 'Autoplay must be turned off for non-volume devices.'
  desc 'Allowing Autoplay to execute may introduce malicious code to a system.  Autoplay begins reading from a drive as soon as media is inserted into the drive.  As a result, the setup file of programs or music on audio media may start.  This setting will disable Autoplay for non-volume devices (such as Media Transfer Protocol (MTP) devices).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoAutoplayfornonVolume

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Disallow Autoplay for non-volume devices" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27063r471434_chk'
  tag severity: 'high'
  tag gid: 'V-225364'
  tag rid: 'SV-225364r569185_rule'
  tag stig_id: 'WN12-CC-000072'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-27051r471435_fix'
  tag 'documentable'
  tag legacy: ['SV-53126', 'V-21973']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
