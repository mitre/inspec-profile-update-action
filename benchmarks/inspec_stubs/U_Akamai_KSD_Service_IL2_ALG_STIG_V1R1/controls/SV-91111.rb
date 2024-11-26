control 'SV-91111' do
  title 'Kona Site Defender must off-load audit records onto a centralized log server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Confirm Kona Site Defender is configured to deliver web logs via the Log Delivery Service (LDS):

1. Log in to the Akamai Luna Portal (Caution-https://control.akamai.com).
2. Click the "Select Group or Property" button.
3. Select the configuration that is being reviewed.
4. Under the "Active Production" section, click on the active version.
5. Under the "Log Request Details" section, verify that "Log Host Header", "Log Referrer Header", and "Log User-Agent Header" are all enabled.
6. Under the "Log Request Details" section, confirm that "Cookie Mode" is set to "Log all cookies" or "Log some cookies" with the applicable cookies specified in the box below.
7. Click the "Configure" tab.
8. Select "Log Delivery".
9. Verify the status is "Active" for the applicable object ID.

If log delivery is not configured properly, this is a finding.'
  desc 'fix', 'Configure Kona Site Defender to deliver web logs via the Log Delivery Service (LDS):

1. Log in to the Akamai Luna Portal (Caution-https://control.akamai.com).
2. Click the "Select Group or Property" button.
3. Select the configuration that is being reviewed.
4. Under the "Active Production" section, click on the active version.
5. Click the "Edit" button (if not already selected).
6. Under the "Log Request Details" section, enable "Log Host Header", "Log Referrer Header", and "Log User-Agent Header".
7. Under the "Log Request Details" section, set "Cookie Mode" is set to "Log all cookies" or "Log some cookies" with the applicable cookies specified in the box below.
8. Click the "Save" button.
9. Activate the configuration by clicking the "Activate" tab and the activate buttons for the proper network (either staging or production).
10. Once the configuration has been propagated to the proper network, click the "Configure" tab.
11. Select "Log Delivery".
12. In the same row as the applicable object ID, click the gear icon under the "Action" column.
13. Select "Begin Log Delivery" and then either "New" or ""Copy"
14. Proceed through the prompts to select the log format and location to send the logs.'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security ALG'
  tag check_id: 'C-76071r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76415'
  tag rid: 'SV-91111r1_rule'
  tag stig_id: 'AKSD-WF-000015'
  tag gtitle: 'SRG-NET-000334-ALG-000050'
  tag fix_id: 'F-83091r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
