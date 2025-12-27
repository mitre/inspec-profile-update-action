control 'SV-224026' do
  title 'The IBM z/OS Policy Agent must contain a policy that protects against or limits the effects of denial-of-service (DoS) attacks by ensuring IBM z/OS is implementing rate-limiting measures on impacted network interfaces.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of the operating system to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Examine the "Policy Agent" policy statements. 

If it can be determined that the policy that protects against or limits the effects of denial-of-service (DoS) attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces, this is not a finding.'
  desc 'fix', 'Develop "Policy Agent" statements to protect against or limit the effects of denial-of-service (DoS) attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25699r516477_chk'
  tag severity: 'medium'
  tag gid: 'V-224026'
  tag rid: 'SV-224026r877866_rule'
  tag stig_id: 'TSS0-OS-000300'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-25687r516478_fix'
  tag 'documentable'
  tag legacy: ['V-98761', 'SV-107865']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
