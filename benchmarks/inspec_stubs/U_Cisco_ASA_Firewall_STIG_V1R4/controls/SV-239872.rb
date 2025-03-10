control 'SV-239872' do
  title 'The Cisco ASA must be configured to generate an alert that can be forwarded to organization-defined personnel and/or the firewall administrator when denial-of-service (DoS) incidents are detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information.

The firewall generates an alert that notifies designated personnel of the Indicators of Compromise (IOCs), which require real-time alerts. These messages should include a severity level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category 1, 2, 4, or 7 detection events) will require an alert when an event is detected.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The firewall must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. The ISSM or ISSO may designate the firewall/system administrator or other authorized personnel to receive the alert within the specified time, validate the alert, and then forward only validated alerts to the ISSM and ISSO.)
  desc 'check', 'NOTE: When operating the ASA in multi-context mode with a separate IDPS, threat detection cannot be enabled, and this check is Not Applicable.

Step 1: Verify that basic and scanning threat detection has been configured as shown below.

threat-detection basic-threat
threat-detection scanning-threat

Step 2: Configure the ASA to send an email to organization-defined personnel and/or the firewall administrator for syslog messages at severity level 4 (warnings) as shown in the example below.

logging mail warnings
logging from-address firewall@mail.mil
logging recipient-address OurFWadmin@mail.mil level warnings
logging recipient-address OurISSO@mail.mil level warnings
…
…
…
smtp-server 10.1.12.33

Note: When a basic threat is detected, the ASA  generates syslog message %ASA-4-733100. When scanning threat is detected, the ASA  generates syslog message %ASA-4-733101. As an alternative to sending email alerts, SNMP traps could be sent to an SIEM that is monitored.

If the ASA is not configured to generate an alert that can be forwarded to the organization-defined personnel and/or firewall administrator when a threat has been detected, this is a finding.'
  desc 'fix', 'Step 1: Configure basic and scanning threat detection as shown below.

ASA(config)# threat-detection basic-threat
ASA(config)# threat-detection scanning-threat

Step 2: Configure the ASA to send an email alert to the organization-defined personnel and/or firewall administrator for syslog messages at severity level 4.

ASA(config)# logging mail 4 
ASA(config)# logging recipient-address OurFWadmin@mail.mil
ASA(config)# logging recipient-address OurISSO@mail.mil
ASA(config)# logging from-address firewall@mail.mil
ASA(config)# smtp-server 10.1.12.33
ASA(config)# end

Note: As an alternative to sending email alerts, SNMP traps could be sent to an SIEM that is monitored.'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43105r863232_chk'
  tag severity: 'medium'
  tag gid: 'V-239872'
  tag rid: 'SV-239872r863233_rule'
  tag stig_id: 'CASA-FW-000300'
  tag gtitle: 'SRG-NET-000392-FW-000042'
  tag fix_id: 'F-43064r665901_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
