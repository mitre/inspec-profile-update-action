control 'SV-253382' do
  title 'Solicited Remote Assistance must not be allowed.'
  desc 'Remote assistance allows another user to view or take control of the local session of a user. Solicited assistance is help that is specifically requested by the local user. This may allow unauthorized parties access to the resources on the computer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fAllowToGetHelp
 
Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Remote Assistance >> "Configure Solicited Remote Assistance" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56835r829228_chk'
  tag severity: 'high'
  tag gid: 'V-253382'
  tag rid: 'SV-253382r829230_rule'
  tag stig_id: 'WN11-CC-000155'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-56785r829229_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
