control 'SV-226194' do
  title 'Windows SmartScreen must be enabled on Windows 2012/2012 R2.'
  desc 'Windows SmartScreen helps protect systems from programs downloaded from the Internet that may be malicious. Warning a user before running downloaded unknown software, at minimum, will help prevent potentially malicious programs from executing.'
  desc 'check', 'This is applicable to unclassified systems; for other systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

Value Name: EnableSmartScreen

Type: REG_DWORD
Value: 0x00000001 (1) (Give user a warning…)
Or 0x00000002 (2) (Require approval…)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> File Explorer >> "Configure Windows SmartScreen" to "Enabled" with either "Give user a warning before running downloaded unknown software" or "Require approval from an administrator before running downloaded unknown software" selected.   

Microsoft has changed this setting several times in the Windows 10 administrative templates, which will affect group policies in a domain if later templates are used.

v1607 of Windows 10 and Windows Server 2016 changed the setting to only Enabled or Disabled without additional selections.  Enabled is effectively "Give user a warning…".

v1703 of Windows 10 or later administrative templates changed the policy name to "Configure Windows Defender SmartScreen", and the selectable options are "Warn" and "Warn and prevent bypass". When either of these are applied to a Windows 2012/2012 R2 system, it will configure the registry equivalent of "Give user a warning…").'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27896r475905_chk'
  tag severity: 'medium'
  tag gid: 'V-226194'
  tag rid: 'SV-226194r794440_rule'
  tag stig_id: 'WN12-CC-000088'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27884r475906_fix'
  tag 'documentable'
  tag legacy: ['SV-51747', 'V-36707']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
