control 'SV-45260' do
  title 'The IDPS must enforce approved authorizations by restricting or blocking the flow of harmful or suspicious communications traffic within the network as defined in the PPSM CAL and vulnerability assessments.'
  desc 'The flow of all communications traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data.

Restricting the flow of communications traffic, also known as Information flow control, regulates where information is allowed to travel as opposed to who is allowed to access the information and without explicit regard to subsequent accesses to that information.

The IDPS will include policy filters, rules, signatures, and behavior analysis algorithms that inspects and restricts traffic based on the characteristics of the information and/or the information path as it crosses internal network boundaries. The IDPS monitors for harmful or suspicious information flows and restricts or blocks this traffic based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'check', 'Verify the IDPS enforces approved authorizations by restricting or blocking the flow of harmful or suspicious communications traffic within the network as defined in the PPSM CAL and vulnerability assessments.

If the IDPS does not enforce approved authorizations by restricting or blocking the flow of harmful or suspicious communications traffic within the network as defined in the PPSM CAL and vulnerability assessments, this is a finding.'
  desc 'fix', 'Configure the IDPS to enforce approved authorizations by restricting or blocking the flow of harmful or suspicious communications traffic within the network as defined in the PPSM CAL and vulnerability assessments.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-42607r3_chk'
  tag severity: 'medium'
  tag gid: 'V-34484'
  tag rid: 'SV-45260r2_rule'
  tag stig_id: 'SRG-NET-000018-IDPS-00018'
  tag gtitle: 'SRG-NET-000018-IDPS-00018'
  tag fix_id: 'F-38656r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
