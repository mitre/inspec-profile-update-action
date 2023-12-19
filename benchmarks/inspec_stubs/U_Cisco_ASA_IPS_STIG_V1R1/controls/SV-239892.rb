control 'SV-239892' do
  title 'The Cisco ASA must be configured to send an alert to organization-defined personnel and/or the firewall administrator when intrusion events are detected.'
  desc 'Without an alert, security personnel may be unaware of intrusion detection incidents that require immediate action and this delay may result in the loss or compromise of information.

In accordance with CCI-001242, the IDPS is a real-time intrusion detection system. These systems must generate an alert when detection events from real-time monitoring occur. Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The IDPS must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. The ISSM or ISSO may designate the firewall administrator and/or other authorized personnel to receive the alert within the specified time, validate the alert, and then forward only validated alerts to the ISSM and ISSO.'
  desc 'check', 'Verify email server and email addresses have been defined.

Step 1: Navigate to Policies >> Actions >> Alerts.

Step 2: From the Create Alert drop-down menu, choose Create Email Alert.

Step 3: Verify that the email address is that of organization-defined personnel and/or the firewall administrator.

If the Cisco ASA is not configured to send an alert to organization-defined personnel and/or the firewall administrator when intrusion events are detected, this is a finding.'
  desc 'fix', 'Configure email server and email addresses to send alerts to organization-defined personnel and/or the firewall administrator.

Step 1: Navigate to Policies >> Actions >> Alerts.

Step 2: From the Create Alert drop-down menu, choose Create Email Alert.

Step 3: Enter a Name for the alert response. In the To field, enter the email addresses where you want to send alerts, separated by commas. In the From field, enter the email address that you want to appear as the sender of the alert. Next to Relay Host, click Edit to enter mail server.

Step 4: Click Save.'
  impact 0.5
  ref 'DPMS Target Cisco ASA IPS'
  tag check_id: 'C-43125r665987_chk'
  tag severity: 'medium'
  tag gid: 'V-239892'
  tag rid: 'SV-239892r665989_rule'
  tag stig_id: 'CASA-IP-000520'
  tag gtitle: 'SRG-NET-000392-IDPS-00214'
  tag fix_id: 'F-43084r665988_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
