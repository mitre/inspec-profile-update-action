control 'SV-227948' do
  title 'The system must not use UDP for NIS/NIS+.'
  desc 'Implementing NIS or NIS+ under UDP may make the system more susceptible to a Denial of Service attack and does not provide the same quality of service as TCP.'
  desc 'check', 'If the system does not use NIS or NIS+, this is not applicable.

Check if NIS or NIS+ is implemented using UDP.

Procedure:
# rpcinfo -p | grep yp | grep udp

If NIS or NIS+ is implemented using UDP, this is a finding.'
  desc 'fix', 'Configure the system to not use UDP for NIS and NIS+.  Consult vendor documentation for the required procedure.'
  impact 0.7
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30110r490264_chk'
  tag severity: 'high'
  tag gid: 'V-227948'
  tag rid: 'SV-227948r603266_rule'
  tag stig_id: 'GEN006380'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-30098r490265_fix'
  tag 'documentable'
  tag legacy: ['V-4399', 'SV-4399']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
