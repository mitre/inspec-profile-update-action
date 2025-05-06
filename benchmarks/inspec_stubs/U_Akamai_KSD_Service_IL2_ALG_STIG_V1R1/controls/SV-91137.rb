control 'SV-91137' do
  title 'Kona Site Defender providing content filtering must be configured to integrate with a system-wide intrusion detection system.'
  desc 'Without coordinated reporting between separate devices, it is not possible to identify the true scale and possible target of an attack.

Integration of the ALG with a system-wide intrusion detection system supports continuous monitoring and incident response programs. This requirement applies to monitoring at internal boundaries using TLS gateways, web content filters, email gateways, and other types of ALGs.

ALGs can work as part of the network monitoring capabilities to off-load inspection functions from the external boundary IDPS by performing more granular content inspection of protocols at the upper layers of the OSI reference model.'
  desc 'check', 'If the SIEM delivery option has been purchased, confirm that the Kona Site Defender SIEM integration is enabled:

1. Log in to the Akamai Luna Portal (https://control.akamai.com).
2. Click the "Configure" tab.
3. Under the "Security" section, select "Security Configuration".
4. If prompted, select "Site Defender" and then "Continue".
5. Open the security configuration for which SIEM data is required.
6. Scroll down to the SIEM Integration section and verify that "Allow data collection for SIEM" is enabled.

If "Allow data collection for SIEM field" is not enabled, this is a finding.'
  desc 'fix', 'Configure Kona Site Defender to deliver security event traffic to the SIEM:

1. Log in to the Akamai Luna Portal (https://control.akamai.com).
2. Click the "Configure" tab.
3. Under the "Security" section, select "Security Configuration".
4. If prompted, select the product with which you would like to work and click "Continue".
5. Open the security configuration for which you want SIEM data.
6. Scroll down to the SIEM Integration section.
7. In the "Allow data collection for SIEM" field, click "Yes".
8. Choose the firewall policies for which you want to export data. Enable SIEM integration for:
   - ALL Firewall policies if you want to send SIEM data for events that violate any/all firewall policies within the security configuration.
   - The following firewall policies if you want data regarding one or more specific firewall policies. In the drop down list, choose the policies you want.
9. Skip the SIEM Event Version field for now.
10. Copy the number in the Security Config ID field. You’ll need it in a minute.
11. Push security configuration changes to the production network.
 - On the upper right of the Security Configuration page, click the Activate button. Under Network, choose Production and click Activate'
  impact 0.3
  ref 'DPMS Target Akamai Edge Security ALG'
  tag check_id: 'C-76101r1_chk'
  tag severity: 'low'
  tag gid: 'V-76441'
  tag rid: 'SV-91137r1_rule'
  tag stig_id: 'AKSD-WF-000032'
  tag gtitle: 'SRG-NET-000383-ALG-000135'
  tag fix_id: 'F-83119r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002656']
  tag nist: ['SI-4 (1)']
end
