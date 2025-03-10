control 'SV-223792' do
  title 'The IBM z/OS Policy Agent must contain a policy that protects against or limits the effects of denial-of-service (DoS) attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.'
  desc 'check', 'Examine the Policy Agent policy statements. 

If it can be determined that policy that protects against or limits the effects of denial-of-service (DoS) attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces, this is not a finding.'
  desc 'fix', 'Develop Policy application and policy agent to protect against or limit the effects of denial-of-service (DoS) attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25465r515064_chk'
  tag severity: 'medium'
  tag gid: 'V-223792'
  tag rid: 'SV-223792r853625_rule'
  tag stig_id: 'RACF-OS-000360'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-25453r515065_fix'
  tag 'documentable'
  tag legacy: ['V-98291', 'SV-107395']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
