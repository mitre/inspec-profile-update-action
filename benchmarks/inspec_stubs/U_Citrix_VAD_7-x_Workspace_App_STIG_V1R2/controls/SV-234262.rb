control 'SV-234262' do
  title 'Citrix Workspace must accept Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the Common Access Card (CAC) to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.

'
  desc 'check', 'Verify the policy value for Administrative Templates >> Citrix Components >> Citrix Workspace >> User authentication >> "Smart card authentication" is not set to "Disabled". For this setting, "Not Configured" is equivalent to "Enabled".

If the "Smart card authentication" policy is set to "Disabled", this is a finding.'
  desc 'fix', 'Set the policy value for Administrative Templates >> Citrix Components >> Citrix Workspace >> User authentication >> "Smart card authentication" to "Enabled" and check the "Allow smart card authentication" box. 

If the environment leverages PIN pass-through, also check the "Use pass-through authentication for PIN" box.'
  impact 0.5
  ref 'DPMS Target Citrix VAD 7.x Workspace App'
  tag check_id: 'C-37447r640181_chk'
  tag severity: 'medium'
  tag gid: 'V-234262'
  tag rid: 'SV-234262r640183_rule'
  tag stig_id: 'CVAD-WS-000855'
  tag gtitle: 'SRG-APP-000391'
  tag fix_id: 'F-37412r640182_fix'
  tag satisfies: ['SRG-APP-000391', 'SRG-APP-000392']
  tag 'documentable'
  tag cci: ['CCI-001953', 'CCI-001954']
  tag nist: ['IA-2 (12)', 'IA-2 (12)']
end
