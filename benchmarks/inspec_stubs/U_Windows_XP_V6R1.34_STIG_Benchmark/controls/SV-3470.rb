control 'SV-3470' do
  title 'The system is configured to allow unsolicited remote assistance offers.'
  desc 'This setting controls whether unsolicited offers of help to this computer are allowed.  The list of users allowed to offer remote assistance to this system is accessed by pressing the Helpers button.'
  desc 'fix', 'Configure the system to prevent unsolicited remote assistance offers by setting the policy value for Computer
Configuration -> Administrative Templates -> System -> Remote Assistance “Offer Remote Assistance” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3470'
  tag rid: 'SV-3470r1_rule'
  tag gtitle: 'Remote Assistance - Offer Remote Assistance'
  tag fix_id: 'F-6776r1_fix'
  tag mitigations: 'Remote Assist - Offer v2'
  tag third_party_tools: 'HK'
  tag mitigation_control: 'This is a documentable finding on workstations with the following mitigations. 
 
-Users must be trained to include the following:  
-Who they can accept assistance offer from.  Offer must be in response to help desk request or confirmed with help desk if unsolicited offer comes through. 
-Users must know how to accept request, allow view or control, and how to disconnect a remote assistance session. 
-Users needs monitor the assistance activity at the workstation while it is occurring. 
 
-The support personnel allowed to offer assistance (helpers) must be limited and documented.   
-Port 3389 should be blocked at the perimeter to prevent other access. 
 
Accounts and groups authorized to offer remote assistance (helpers) are identified in the following registry key. 
 
Registry Hive:	HKEY_LOCAL_MACHINE 
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\ RAUnsolicit\\ 
 
Each Account or group will be listed under a separate value name with the value equaling the value name as in the following examples. 
 
Value Name:  Administrators 
Type:  REG_SZ 
Value:  Administrators 
 
Value Name:  TestUser 
Type:   REG_SZ 
Value:  TestUser'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
