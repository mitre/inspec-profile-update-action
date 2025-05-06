control 'SV-225325' do
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
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27024r471317_chk'
  tag severity: 'medium'
  tag gid: 'V-225325'
  tag rid: 'SV-225325r569185_rule'
  tag stig_id: 'WN12-CC-000012'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27012r471318_fix'
  tag 'documentable'
  tag legacy: ['V-15698', 'SV-53085']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
