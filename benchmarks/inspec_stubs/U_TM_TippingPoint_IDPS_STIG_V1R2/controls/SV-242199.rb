control 'SV-242199' do
  title 'The TPS must generate a log record so an alert can be configured to, at a minimum, the system administrator when malicious code is detected.'
  desc 'Without an alert, security personnel may be unaware of an impending failure of the audit capability, and the ability to perform forensic analysis and detect rate-based and other anomalies will be impeded.

The TPS generates an immediate (within seconds) alert which notifies designated personnel of the incident. Sending a message to an unattended log or console does not meet this requirement since that will not be seen immediately. These messages should include a severity level indicator or code as an indicator of the criticality of the incident.

'
  desc 'check', '1. In the Trend Micro SMS, navigate to "Profiles" and "Shared Settings". 
2. Under "Action Sets, if "Remote Syslog", are not enabled for both the "Block+Notify" and "Block+Notify+Trace", this is a finding.'
  desc 'fix', '1. In the Trend Micro SMS, navigate to "Profiles" and "Shared Settings". 
2. Under "Action Sets: 
   a. Select "Block+Notify" and edit. 
   b. Select Notifications, and check "Remote Syslog". 
   c. Select "Finish".'
  impact 0.7
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45474r710138_chk'
  tag severity: 'high'
  tag gid: 'V-242199'
  tag rid: 'SV-242199r754438_rule'
  tag stig_id: 'TIPP-IP-000360'
  tag gtitle: 'SRG-NET-000248-IDPS-00206'
  tag fix_id: 'F-45432r710139_fix'
  tag satisfies: ['SRG-NET-000248-IDPS-00206', 'SRG-NET-000249-IDPS-00222', 'SRG-NET-000385-IDPS-00210']
  tag 'documentable'
  tag cci: ['CCI-001242', 'CCI-001243', 'CCI-002684']
  tag nist: ['SI-3 c 1', 'SI-3 c 2', 'SI-4 (22) (b)']
end
