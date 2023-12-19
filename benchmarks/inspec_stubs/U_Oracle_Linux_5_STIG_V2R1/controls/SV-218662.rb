control 'SV-218662' do
  title 'The system must not use UDP for NIS/NIS+.'
  desc 'Implementing Network Information Service (NIS) or NIS+ under UDP may make the system more susceptible to a Denial of Service attack and does not provide the same quality of service as TCP.'
  desc 'check', 'If the system does not use NIS or NIS+, this is not applicable.

Check if NIS or NIS+ is implemented using UDP.

Procedure:
# rpcinfo -p | grep yp | grep udp

If NIS or NIS+ is implemented using UDP, this is a finding.'
  desc 'fix', 'Configure the system to not use UDP for NIS and NIS+. Consult vendor documentation for the required procedure.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20137r562906_chk'
  tag severity: 'high'
  tag gid: 'V-218662'
  tag rid: 'SV-218662r603259_rule'
  tag stig_id: 'GEN006380'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20135r562907_fix'
  tag 'documentable'
  tag legacy: ['V-4399', 'SV-63813']
  tag cci: ['CCI-000381', 'CCI-001436']
  tag nist: ['CM-7 a', 'AC-17 (8)']
end
