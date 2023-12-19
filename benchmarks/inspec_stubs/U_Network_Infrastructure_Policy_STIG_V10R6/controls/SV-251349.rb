control 'SV-251349' do
  title 'Tunneling of classified traffic across an unclassified IP transport network or service provider backbone must be documented in the enclaves security authorization package and an Approval to Connect (ATC), or an Interim ATC must be issued by DISA prior to implementation.'
  desc "CJCSI 6211.02D instruction establishes policy and responsibilities for the connection of any information systems to the Defense Information Systems Network (DISN) provided transport. Enclosure E mandates that the CC/S/A document all IP tunnels transporting classified communication traffic in the enclave's security authorization package prior to implementation. An ATC or IATC amending the current connection approval must be in place prior to implementation.

Enclosure D of the CJCSI 6211.02D also provides guidance on the requirements of tunneling classified data (section 15.a), which helps a CC/S/A determine applicability to their mission. Items include but are not limited to: 
- minimize tunneling of classified data over transport other than DISN provided transport (i.e., SIPRNET);
- ensure the Authorizing Official (DAA) validates all requirements to tunnel classified information across unclassified IP infrastructure;
- obtain DSAWG approval before tunneling classified data across unclassified IP infrastructure;
- ensure transmission of classified information is secured through use of authorized cryptographic equipment and algorithms and/or PDSs;
- document IP tunnels transporting classified communication traffic in the enclave’s security authorization package prior to implementation;
- an ATC or IATC amending the current connection approval must be in place prior to implementation."
  desc 'check', "Review the enclave's security authorization package and the ATC or Interim ATC amending the connection approval received.

If the tunneling of classified traffic is not documented in the security authorization package and an ATC or Interim ATC, this is a finding."
  desc 'fix', 'Document the tunneling of classified traffic in the security authorization package and the ATC or Interim ATC.'
  impact 0.7
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54784r806000_chk'
  tag severity: 'high'
  tag gid: 'V-251349'
  tag rid: 'SV-251349r916231_rule'
  tag stig_id: 'NET-TUNL-028'
  tag gtitle: 'NET-TUNL-028'
  tag fix_id: 'F-54737r806001_fix'
  tag 'documentable'
  tag legacy: ['V-14738', 'SV-15494']
  tag cci: ['CCI-002396', 'CCI-002418']
  tag nist: ['SC-7 (4) (c)', 'SC-8']
end
