control 'SV-91113' do
  title 'Kona Site Defender must off-load audit records onto a centralized log server in real time.'
  desc 'Off-loading ensures audit information does not get overwritten if the limited audit storage capacity is reached and also protects the audit record in case the system/component being audited is compromised.

Off-loading is a common process in information systems with limited audit storage capacity. The audit storage on the ALG is used only in a transitory fashion until the system can communicate with the centralized log server designated for storing the audit records, at which point the information is transferred. However, DoD requires that the log be transferred in real time, which indicates that the time from event detection to off-loading is seconds or less.

This does not apply to audit logs generated on behalf of the device itself (management).'
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
  tag check_id: 'C-76073r1_chk'
  tag severity: 'low'
  tag gid: 'V-76417'
  tag rid: 'SV-91113r1_rule'
  tag stig_id: 'AKSD-WF-000016'
  tag gtitle: 'SRG-NET-000511-ALG-000051'
  tag fix_id: 'F-83093r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
