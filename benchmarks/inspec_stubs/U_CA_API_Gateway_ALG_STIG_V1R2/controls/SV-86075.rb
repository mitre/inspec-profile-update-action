control 'SV-86075' do
  title 'The CA API Gateway providing content filtering must be configured to integrate with a system-wide intrusion detection system.'
  desc 'Without coordinated reporting between separate devices, it is not possible to identify the true scale and possible target of an attack.

Integration of the ALG with a system-wide intrusion detection system supports continuous monitoring and incident response programs. This requirement applies to monitoring at internal boundaries using TLS gateways, web content filters, email gateways, and other types of ALGs.

ALGs can work as part of the network monitoring capabilities to off-load inspection functions from the external boundary Intrusion Detection and Prevention System (IDPS) by performing more granular content inspection of protocols at the upper layers of the Open Systems Interconnection (OSI) reference model.

The CA API Gateway must be configured to integrate with an ICAP enabled Intrusion Detection System such as McAfee, Sophos, or Symantec.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services that require scanning for intrusion detection. 

Verify the "Scan Using ICAP-Enabled Antivirus" Assertion is included in the policy. If it is not, check to see if it has been added to a Global Policy. 

If the Assertion is not present in either Global or Registered Services policy, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services that did not have the "Scan Using ICAP-Enabled Antivirus" Assertion.

Add the "Scan Using ICAP-Enabled Antivirus" Assertion, configure the parameters for the Assertion in accordance with organizational requirements, and click the "Save and Activate" button. 

If the organization requires that all Registered Services require integration with an intrusion detection system, consider adding the "Scan Using ICAP-Enabled Antivirus" Assertion to a Global Policy to meet this requirement.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71841r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71451'
  tag rid: 'SV-86075r1_rule'
  tag stig_id: 'CAGW-GW-000720'
  tag gtitle: 'SRG-NET-000383-ALG-000135'
  tag fix_id: 'F-77771r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002656']
  tag nist: ['SI-4 (1)']
end
