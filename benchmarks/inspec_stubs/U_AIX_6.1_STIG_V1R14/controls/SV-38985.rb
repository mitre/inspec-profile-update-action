control 'SV-38985' do
  title "The system's local firewall must implement a deny-all, allow-by-exception policy."
  desc 'A local firewall protects the system from exposing unnecessary or undocumented network services to the local enclave.  If a system within the enclave is compromised, firewall protection on an individual system continues to protect it from attack.'
  desc 'check', "Determine if the system's local firewall implements a deny-all, allow-by-exception policy. 

View the firewall (filter rules) with smit or lsfilt commands.

# smitty ipsec4

# lsfilt

If there is not a deny-all,  allow-by-exception policy, this is a finding."
  desc 'fix', "Configure the system's local firewall to implement a deny-all, 
allow-by-exception policy.

Firewall rules can be added and activated with SMIT ipsec4 or genfilt command.

#smitty ipsec4"
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37938r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22583'
  tag rid: 'SV-38985r1_rule'
  tag stig_id: 'GEN008540'
  tag gtitle: 'GEN008540'
  tag fix_id: 'F-33194r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']
end
