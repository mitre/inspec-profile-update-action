control 'SV-104301' do
  title 'Symantec ProxySG providing content filtering must generate an alert to, at a minimum, the ISSO and ISSM when denial-of-service (DoS) incidents are detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information.

The ALG generates an alert that notifies designated personnel of the Indicators of Compromise (IOCs) that require real-time alerts. These messages should include a severity level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise. Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category 1, 2, 4, or 7 detection events) will require an alert when an event is detected.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.)
  desc 'check', 'Verify that DoS events generate alerts to at least the ISSO and ISSM.

1. SSH into the ProxySG console and type "enable".
2. Enter the correct password and type "config". 
3. Press "Enter" and type "show attack-detection configuration". 
4. Verify that "client limits enabled" equals "true".
5. Log on to the Web Management Console.
6. Browse to Maintenance >> Event Logging and click the "Mail" tab. Verify that the ISSO and ISSM email addresses are specified.
7. Browse to Configuration >> Policy >> Visual Policy Manager. Click "Launch".
8. In each Web Access Layer, find rules that contain an "Action" of "Attack Detection". 
9. Verify that the "Track" field of these rules is set to "Email" and that the "recipients" are set to at least the ISSO and ISSM.

If Symantec ProxySG providing content filtering does not generate an alert to, at a minimum, the ISSO and ISSM when DoS incidents are detected, this is a finding.'
  desc 'fix', 'Configure the ProxySG to email DoS attack detection/mitigation alerts to the ISSO and ISSM. 

1. SSH into the ProxySG console and type "enable".
2. Enter the correct password and type "config".
3. Press "Enter" and type "attack-detection". 
4. See the ProxySG Administration Guide, Chapter 73: Preventing Denial of Service Attacks, to understand the functionality before proceeding.
5. Type "client" and press "Enter". Type "enable-limits" and press "Enter".
6. Log on to the Web Management Console.
7. Browse to Maintenance >> Event Logging and click the "Mail" tab. Ensure that the ISSO and ISSM email addresses are specified.
8. Browse to Configuration >> Policy >> Visual Policy Manager. Click "Launch".
9. In one Web Access Layer, create a new rule. Right-click the "Action" of that rule and select "Set". Click "New" and select "Set Attack Detection". Provide a "Failure Weight" per local security policy requirements.
10. Click "OK" and click "OK" again. 
11. Right-click the "Track" column for this rule and select "Set". Click "New" and select "Email". 
12. Select "Custom Recipients" and click "Configure Custom Recipients Lists".
13. Click "New," provide a name for the list, and enter the ISSO and ISSM email addresses in the "List Members" field.
14. Click "OK" and click "OK" again. Create message text and click "OK".
15. Click "OK" and click "OK" again. Select File >> Install Policy on SG Appliance.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93533r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94347'
  tag rid: 'SV-104301r1_rule'
  tag stig_id: 'SYMP-AG-000670'
  tag gtitle: 'SRG-NET-000392-ALG-000148'
  tag fix_id: 'F-100463r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
