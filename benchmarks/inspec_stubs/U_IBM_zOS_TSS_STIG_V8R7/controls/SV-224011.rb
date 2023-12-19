control 'SV-224011' do
  title 'The IBM z/OS Policy Agent must contain a policy that manages excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of denial-of-service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.'
  desc 'check', 'Examine the Policy Agent policy statements. 

If it can be determined that there are policy statements that manages excess capacity, this is not a finding.'
  desc 'fix', 'Develop Policy application and Policy agent to manage excess capacity.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25684r516432_chk'
  tag severity: 'medium'
  tag gid: 'V-224011'
  tag rid: 'SV-224011r561402_rule'
  tag stig_id: 'TSS0-OS-000150'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-25672r516433_fix'
  tag 'documentable'
  tag legacy: ['SV-107835', 'V-98731']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
