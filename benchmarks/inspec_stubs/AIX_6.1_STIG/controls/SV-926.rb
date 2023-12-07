control 'SV-926' do
  title 'Any NIS+ server must be operating at security level 2.'
  desc 'If the NIS+ server is not operating in, at least, security level 2, there is no encryption and the system could be penetrated by intruders and/or malicious users.'
  desc 'check', 'If the system is not using NIS+, this is not applicable.

Check the system to determine if NIS+ security level 2 is implemented.

Procedure:
# niscat cred.org_dir 

If the second column does not contain DES, the system is not using NIS+ security level 2, and this is a finding.'
  desc 'fix', 'Configure the NIS+ server to use security level 2.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-852r2_chk'
  tag severity: 'medium'
  tag gid: 'V-926'
  tag rid: 'SV-926r2_rule'
  tag stig_id: 'GEN006460'
  tag gtitle: 'GEN006460'
  tag fix_id: 'F-25778r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001435']
  tag nist: ['AC-17 (8)']
end
