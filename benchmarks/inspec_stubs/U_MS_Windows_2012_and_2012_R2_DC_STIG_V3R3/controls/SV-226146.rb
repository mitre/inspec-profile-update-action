control 'SV-226146' do
  title 'The configuration of wireless devices using Windows Connect Now must be disabled.'
  desc 'Windows Connect Now allows the discovery and configuration of devices over wireless.  Wireless devices must be managed.  If a rogue device is connected to a system, there is potential for sensitive information to be compromised.'
  desc 'check', 'If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars\\

Value Name: DisableFlashConfigRegistrar
Value Name: DisableInBand802DOT11Registrar
Value Name: DisableUPnPRegistrar
Value Name: DisableWPDRegistrar
Value Name: EnableRegistrars

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Windows Connect Now -> "Configuration of wireless settings using Windows Connect Now" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27848r475761_chk'
  tag severity: 'medium'
  tag gid: 'V-226146'
  tag rid: 'SV-226146r794417_rule'
  tag stig_id: 'WN12-CC-000012'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27836r475762_fix'
  tag 'documentable'
  tag legacy: ['V-15698', 'SV-53085']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
