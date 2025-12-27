control 'SV-239888' do
  title 'The Cisco ASA must be configured to send an alert to organization-defined personnel and/or the firewall administrator when malicious code is detected.'
  desc 'Without an alert, security personnel may be unaware of an impending failure of the audit capability, and the ability to perform forensic analysis and detect rate-based and other anomalies will be impeded.

The IDPS generates an immediate (within seconds) alert which notifies designated personnel of the incident. Sending a message to an unattended log or console does not meet this requirement since that will not be seen immediately. These messages should include a severity level indicator or code as an indicator of the criticality of the incident. The ISSM or ISSO may designate the firewall administrator and/or other authorized personnel to receive the alert within the specified time, validate the alert, and then forward only validated alerts to the ISSM and ISSO.'
  desc 'check', 'Verify email server and email addresses have been defined.

Step 1: Navigate to Policies >> Actions >> Alerts.

Step 2: From the Create Alert drop-down menu, choose Create Email Alert.

Step 3: Verify the email address is that of the system administrator.
----------------------------------------
Verify that Advanced Malware Protection is configured to generate alerts.

Step 1: Navigate to Policies >> Actions >> Alerts.

Step 2: Click the Advanced Malware Protections Alerts tab.

Step 3: In the Alerts section, verify that an email alert has been selected.

Note: The above example is using the Firepower Management Center.

If the ASA is not configured to send an alert to organization-defined personnel and/or the firewall administrator when malicious code is detected, this is a finding.'
  desc 'fix', 'Configure email server and email addresses to send alerts to organization-defined personnel and/or the firewall administrator.

Step 1: Navigate to Policies >> Actions >> Alerts.

Step 2: From the Create Alert drop-down menu, choose Create Email Alert.

Step 3: Enter a Name for the alert response. In the To field, enter the email addresses where you want to send alerts, separated by commas. In the From field, enter the email address that you want to appear as the sender of the alert. Next to Relay Host, click edit to enter mail server.

Step 4: Click Save.
----------------------------------------------
Configure Advanced Malware Protection to send alerts when malware is detected.

Step 1: Navigate to Policies >> Actions >> Alerts.

Step 2: Click the Advanced Malware Protections Alerts tab.

Step 3: In the Alerts section, choose the alert response for an email alert.

Step 4: Click Save.'
  impact 0.5
  ref 'DPMS Target Cisco ASA IPS'
  tag check_id: 'C-43121r665975_chk'
  tag severity: 'medium'
  tag gid: 'V-239888'
  tag rid: 'SV-239888r665977_rule'
  tag stig_id: 'CASA-IP-000280'
  tag gtitle: 'SRG-NET-000249-IDPS-00222'
  tag fix_id: 'F-43080r665976_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
