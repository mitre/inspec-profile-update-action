control 'SV-15494' do
  title 'Tunneling of classified traffic across an unclassified IP transport network or service provider backbone must be documented in the enclaves security authorization package and an Approval to Connect (ATC), or an Interim ATC must be issued by DISA prior to implementation.'
  desc 'CJCSI 6211.02D instruction establishes policy and responsibilities for the connection of any information systems to the Defense Information Systems Network (DISN) provided transport. Enclosure E mandates that the CC/S/A document all IP tunnels transporting classified communication traffic in the enclave’s security authorization package prior to implementation. An ATC or IATC amending the current connection approval must be in place prior to implementation.'
  desc 'check', "Review the enclave's security authorization package and the ATC or Interim ATC amending the connection approval received.

If the tunneling of classified traffic is not documented in the security authorization package and an ATC or Interim ATC, this is a finding."
  desc 'fix', 'Document the tunneling of classified traffic in the security authorization package and the ATC or Interim ATC.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-12960r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14738'
  tag rid: 'SV-15494r3_rule'
  tag stig_id: 'NET-TUNL-028'
  tag gtitle: 'Unapproved SIPRNet traffic exists'
  tag fix_id: 'F-14204r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002396', 'CCI-002418']
  tag nist: ['SC-7 (4) (c)', 'SC-8']
end
