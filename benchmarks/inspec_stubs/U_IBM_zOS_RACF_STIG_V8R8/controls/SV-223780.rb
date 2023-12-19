control 'SV-223780' do
  title 'The IBM z/OS Policy Agent must employ a deny-all, allow-by-exception firewall policy for allowing connections to other systems.'
  desc 'Failure to restrict network connectivity only to authorized systems permits inbound connections from malicious systems. It also permits outbound connections that may facilitate exfiltration of DoD data.'
  desc 'check', 'Examine the policy agent policy statements. 

If it can be determined that the policy agent employs a deny-all, allow-by exception firewall policy for allowing connections to other systems this is not a finding.'
  desc 'fix', 'Develop a policy application and policy agent to employ a deny-all, allow-by-exception firewall policy for allowing connections to other systems.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25453r515028_chk'
  tag severity: 'medium'
  tag gid: 'V-223780'
  tag rid: 'SV-223780r853620_rule'
  tag stig_id: 'RACF-OS-000240'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-25441r515029_fix'
  tag 'documentable'
  tag legacy: ['V-98267', 'SV-107371']
  tag cci: ['CCI-000366', 'CCI-002080']
  tag nist: ['CM-6 b', 'CA-3 (5)']
end
