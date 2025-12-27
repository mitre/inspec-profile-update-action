control 'SV-45262' do
  title 'The IDPS must restrict or block harmful or suspicious communications traffic between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'The IDPS enforces approved authorizations by controlling the flow of information between interconnected networks to prevent harmful or suspicious traffic does spread to these interconnected networks.

Information flow control policies and restrictions govern where information is allowed to travel as opposed to who is allowed to access the information. The IDPS includes policy filters, rules, signatures, and behavior analysis algorithms that inspects and restricts traffic based on the characteristics of the information and/or the information path as it crosses external/perimeter boundaries. IDPS components are installed and configured such that they restrict or block detected harmful or suspect information flows based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'check', 'Verify the IDPS enforces approved authorizations by restricting or blocking the flow of harmful or suspicious communications traffic for controlling the flow of information between interconnected networks as defined in the PPSM CAL and vulnerability assessments.

If the IDPS does not enforce approved authorizations by restricting or blocking the flow of harmful or suspicious communications traffic for controlling the flow of information between interconnected networks as defined in the PPSM CAL and vulnerability assessments, this is a finding.'
  desc 'fix', 'Configure the IDPS to enforce approved authorizations by restricting or blocking the flow of harmful or suspicious communications traffic for controlling the flow of information between interconnected networks as defined in the PPSM CAL and vulnerability assessments.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-42609r2_chk'
  tag severity: 'medium'
  tag gid: 'V-34485'
  tag rid: 'SV-45262r2_rule'
  tag stig_id: 'SRG-NET-000019-IDPS-00019'
  tag gtitle: 'SRG-NET-000019-IDPS-00019'
  tag fix_id: 'F-38658r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
