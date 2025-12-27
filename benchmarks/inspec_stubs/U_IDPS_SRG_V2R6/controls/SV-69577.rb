control 'SV-69577' do
  title 'The IDPS must provide an alert to, at a minimum, the system administrator and ISSO when any audit failure events occur.'
  desc 'Without an alert, security personnel may be unaware of an impending failure of the audit capability, and the ability to perform forensic analysis may be impeded.

This requirement includes, but is not limited to, failures where the detection and/or prevention function is unable to write events to either local storage or the centralized server. The IDPS must generate an alert which will notify designated personnel of the logging failure. Alerts provide organizations with urgent messages. The alert must provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less). Alert messages must include the severity level.

The IDPS must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. The ISSM or ISSO may designate the system administrator or other authorized personnel to receive the alert within the specified time, validate the alert, then forward only validated alerts to the ISSO.'
  desc 'check', 'Verify the IDPS provides an alert to, at a minimum, the system administrator and ISSO when any audit failure events occur.

If the IDPS does not provide an alert to, at a minimum, the system administrator and ISSO when any audit failure events occur, this is a finding.'
  desc 'fix', 'Configure the IDPS to provide an alert to, at a minimum, the system administrator and ISSO when any audit failure events occur.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55953r5_chk'
  tag severity: 'medium'
  tag gid: 'V-55331'
  tag rid: 'SV-69577r3_rule'
  tag stig_id: 'SRG-NET-000335-IDPS-00014'
  tag gtitle: 'SRG-NET-000335-IDPS-00014'
  tag fix_id: 'F-60197r4_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
