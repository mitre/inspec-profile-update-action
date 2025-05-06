control 'SV-223560' do
  title 'IBM z/OS Policy Agent must employ a deny-all, allow-by-exception firewall policy for allowing connections to other systems.'
  desc 'Failure to restrict network connectivity only to authorized systems permits inbound connections from malicious systems. It also permits outbound connections that may facilitate exfiltration of DoD data.'
  desc 'check', 'Examine the Policy Agent policy statements. 

If it can be determined that the policy agent employs a deny-all, allow-by exception firewall policy for allowing connections to other systems, this is not a finding.'
  desc 'fix', 'Develop a policy application and policy agent to employ a deny-all, allow-by-exception firewall policy for allowing connections to other systems.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25233r504707_chk'
  tag severity: 'medium'
  tag gid: 'V-223560'
  tag rid: 'SV-223560r533198_rule'
  tag stig_id: 'ACF2-OS-000240'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-25221r504708_fix'
  tag 'documentable'
  tag legacy: ['V-97825', 'SV-106929']
  tag cci: ['CCI-000366', 'CCI-002080']
  tag nist: ['CM-6 b', 'CA-3 (5)']
end
