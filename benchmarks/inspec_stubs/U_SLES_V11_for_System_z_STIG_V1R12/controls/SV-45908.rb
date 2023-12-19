control 'SV-45908' do
  title 'The system must not use UDP for NIS/NIS+.'
  desc 'Implementing Network Information Service (NIS) or NIS+ under UDP may make the system more susceptible to a Denial of Service attack and does not provide the same quality of service as TCP.'
  desc 'check', 'If the system does not use NIS or NIS+, this is not applicable.

Check if NIS or NIS+ is implemented using UDP.

Procedure:
# rpcinfo -p | grep yp | grep udp

If NIS or NIS+ is implemented using UDP, this is a finding.'
  desc 'fix', 'Configure the system to not use UDP for NIS and NIS+. Consult vendor documentation for the required procedure.'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43216r1_chk'
  tag severity: 'high'
  tag gid: 'V-4399'
  tag rid: 'SV-45908r1_rule'
  tag stig_id: 'GEN006380'
  tag gtitle: 'GEN006380'
  tag fix_id: 'F-39286r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
