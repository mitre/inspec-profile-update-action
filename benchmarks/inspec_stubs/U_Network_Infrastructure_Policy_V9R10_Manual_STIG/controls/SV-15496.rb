control 'SV-15496' do
  title 'DSAWG approval must be obtained before tunneling classified traffic outside the components local area network boundaries across a non-DISN or OCONUS DISN unclassified IP wide area network transport infrastructure.'
  desc 'CJCSI 6211.02E instruction establishes policy and responsibilities for the connection of any information systems to the Defense Information Systems Network (DISN) provided transport. Enclosure E mandates that the CC/S/A obtain DSAWG approval before tunneling classified data outside component’s local area network boundaries across a non-DISN or OCONUS DISN unclassified IP-wide area transport infrastructure.'
  desc 'check', 'Review the network topology diagram.

If there is a connection between the classified network and the unclassified network for the purpose of tunneling classified traffic across a non-DISN or OCONUS DISN unclassified IP network, verify there is approval by the DSAWG.

If there is no document stating DSAWG approval, this is a finding.'
  desc 'fix', 'Remove the connection between the classified and unclassified network. Obtain approval from the DSAWG for the purpose of tunneling classified traffic across a non-DISN or OCONUS DISN unclassified IP network.'
  impact 0.7
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-12962r3_chk'
  tag severity: 'high'
  tag gid: 'V-14740'
  tag rid: 'SV-15496r2_rule'
  tag stig_id: 'NET-TUNL-030'
  tag gtitle: 'SIPRNet traffic exists on a ISP'
  tag fix_id: 'F-14206r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002396', 'CCI-002418']
  tag nist: ['SC-7 (4) (c)', 'SC-8']
end
