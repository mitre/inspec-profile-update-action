control 'SV-55746' do
  title 'IP-based VTC systems must not connect to ISDN lines when connected to a classified network.'
  desc 'Most CODECs have a built-in IMUX such that multiple ISDN lines can terminate directly on the CODEC. ISDN lines used for VTC transport are provided by a traditional telephone switch on an unclassified network. Connecting a classified IP network to an unclassified telephone network through a VTC CODEC while in a conference could lead to disclosure of classified information to the unclassified network and unclassified VTC endpoints. While this issue might be mitigated by using a Type 1 encryptor between the CODEC and an external IMUX, an SOP would need to be in place which would dictate that the ISDN connection must be established and the Type 1 encryptor synced with the other end BEFORE the CODEC was connected to the classified IP network. This type of operation is risky and prone to error and is therefore not recommended.'
  desc 'check', 'Review the VTC system architecture and inspect the VTC CODEC to verify that ISDN lines are not connected directly to the CODEC if it connects to a classified IP network (e.g., SIPRNet, JWICS) at any time. If they are, this is a finding.

Note: If the VTC system is used to support multiple networks having different classification levels, and the ISDN lines are isolated from classified IP, they must meet periods processing requirements.'
  desc 'fix', 'Do not simultaneously connect ISDN lines to a VTC CODEC if the CODEC connects to a classified IP network.'
  impact 0.7
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49174r4_chk'
  tag severity: 'high'
  tag gid: 'V-43017'
  tag rid: 'SV-55746r2_rule'
  tag stig_id: 'RTS-VTC 7040'
  tag gtitle: 'RTS-VTC 7040'
  tag fix_id: 'F-48601r4_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'EBCR-1'
end
