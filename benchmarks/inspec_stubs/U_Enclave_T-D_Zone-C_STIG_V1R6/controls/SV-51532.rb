control 'SV-51532' do
  title 'Tunneling mechanisms must be used for data transmission between interconnected organizations.'
  desc 'Using tunnels will prohibit data shared between interconnecting sites from leaking onto untrusted networks.  These mechanisms are vital for transit over an untrusted network so sensitive information is not accidentally leaked onto the DISN or a non-DoD network.  Typical tunnel mechanisms found in use today include, but are not limited to, IPSec, MPLS, GRE, and TACLANE.'
  desc 'check', 'Review the network diagrams to determine whether a tunnel is being used for transport across any untrusted network, such as the DISN or ISP.  If a tunnel mechanism is not being used to carry information to other organizations over an untrusted network, this is a finding.'
  desc 'fix', 'Engineer a solution to establish tunnel mechanisms interconnected between organizations over untrusted networks.'
  impact 0.7
  ref 'DPMS Target Test Enclave - Zone C'
  tag check_id: 'C-46820r1_chk'
  tag severity: 'high'
  tag gid: 'V-39665'
  tag rid: 'SV-51532r1_rule'
  tag stig_id: 'ENTD0260'
  tag gtitle: 'ENTD0260 - Tunneling mechanism not used for transport.'
  tag fix_id: 'F-44673r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECIC-1, ECSC-1'
end
