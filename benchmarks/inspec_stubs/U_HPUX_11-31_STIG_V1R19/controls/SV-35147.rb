control 'SV-35147' do
  title 'The system must not use UDP for Network Information System (NIS/NIS+).'
  desc 'Implementing NIS or NIS+ under UDP may make the system more susceptible to a Denial of Service attack and does not provide the same quality of service as TCP.'
  desc 'check', 'If the system does not use NIS or NIS+, this is not applicable.

Check if NIS or NIS+ is implemented using UDP.
# rpcinfo -p | grep yp | grep udp

If NIS or NIS+ is implemented using UDP, this is a finding.'
  desc 'fix', 'Configure the system to not use UDP for NIS and NIS+. HP-UX specific documentation (note the major version of NIS+ currently running) should be consulted for the required procedure.'
  impact 0.7
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36719r1_chk'
  tag severity: 'high'
  tag gid: 'V-4399'
  tag rid: 'SV-35147r1_rule'
  tag stig_id: 'GEN006380'
  tag gtitle: 'GEN006380'
  tag fix_id: 'F-30298r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
