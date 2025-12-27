control 'SV-253276' do
  title 'Simple Network Management Protocol (SNMP) must not be installed on the system.'
  desc '"SNMP" is not installed by default. Some protocols and services do not support required security features, such as encrypting passwords or traffic.'
  desc 'check', 'Verify SNMP has not been installed.

Navigate to the Windows\\System32 directory.

If the "SNMP" application exists, this is a finding.'
  desc 'fix', 'Uninstall "Simple Network Management Protocol (SNMP)" from the system.

Run "Programs and Features".
Select "Turn Windows Features on or off".
De-select "Simple Network Management Protocol (SNMP)".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56729r828910_chk'
  tag severity: 'medium'
  tag gid: 'V-253276'
  tag rid: 'SV-253276r828912_rule'
  tag stig_id: 'WN11-00-000105'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-56679r828911_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
