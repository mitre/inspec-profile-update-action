control 'SV-224006' do
  title 'The IBM z/OS Policy Agent must be configured to deny-all, allow-by-exception firewall policy for allowing connections to other systems.'
  desc 'Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Examine the policy agent policy statements. If it can be determined that the policy agent employs a deny-all, allow-by exception firewall policy for allowing connections to other systems this is not a finding.'
  desc 'fix', 'Develop a policy application and policy agent to employ a deny-all, allow-by-exception firewall policy for allowing connections to other systems.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25679r516417_chk'
  tag severity: 'medium'
  tag gid: 'V-224006'
  tag rid: 'SV-224006r877847_rule'
  tag stig_id: 'TSS0-OS-000100'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-25667r516418_fix'
  tag 'documentable'
  tag legacy: ['V-98719', 'SV-107823']
  tag cci: ['CCI-000366', 'CCI-002080']
  tag nist: ['CM-6 b', 'CA-3 (5)']
end
