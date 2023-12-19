control 'SV-96143' do
  title 'Citrix Receiver must accept Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.

'
  desc 'check', 'Verify the policy value for Administrative Templates >> Classic Administrative Templates (ADM) >> Citrix Components >> Citrix Receiver >> User authentication >> "Local user name and password" is set to "Enabled" with the option "Enable pass-through authentication" checked. 

If the "Local user name and password" policy is not "Enabled" or does not have the "Enable pass-through authentication" option checked, this is a finding.'
  desc 'fix', 'Set the policy value for Administrative Templates >> Classic Administrative Templates (ADM) >> Citrix Components >> Citrix Receiver >> User authentication >> Local user name and password to "Enabled" and select the option "Enable pass-through authentication".'
  impact 0.5
  ref 'DPMS Target XenDesktop 7.x Receiver'
  tag check_id: 'C-81169r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81429'
  tag rid: 'SV-96143r1_rule'
  tag stig_id: 'CXEN-RE-000855'
  tag gtitle: 'SRG-APP-000391'
  tag fix_id: 'F-88247r1_fix'
  tag satisfies: ['SRG-APP-000391', 'SRG-APP-000392']
  tag 'documentable'
  tag cci: ['CCI-001953', 'CCI-001954']
  tag nist: ['IA-2 (12)', 'IA-2 (12)']
end
