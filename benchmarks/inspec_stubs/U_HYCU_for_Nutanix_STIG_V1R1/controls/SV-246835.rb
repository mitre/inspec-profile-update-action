control 'SV-246835' do
  title 'The HYCU server must produce audit records containing information to establish when events occurred, where events occurred, the source of the event, the outcome of the event, and identity of any individual or process associated with the event.'
  desc 'It is essential for security personnel to know what is being done, what was attempted, where it was done, when it was done, and by whom it was done in order to compile an accurate risk assessment. Logging the date and time of each detected event provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network device. In order to establish and correlate the series of events leading up to an outage or attack, it is imperative the date and time are recorded in all log records. 

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as device hardware components, device software modules, session identifiers, filenames, host names, and functionality.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the source of the event. The source may be a component, module, or process within the device or an external session, administrator, or device. 

Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the device after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.

'
  desc 'check', 'Check the contents of the "/var/log/audit/audit.log" file.

HYCU also maintains Event (Audit) information in the "HYCU Web UI Events" menu. 

Verify the audit log contains records for:
- When (date and time) of events occurred
- Where events occurred
- The source of the event(s)
- The outcome of the event(s)
- The identity of any individual or process associated with the event(s)

If the audit log is not configured or does not have required contents, this is a finding.'
  desc 'fix', 'Log on to the HYCU VM console and load the STIG audit rules by using the following commands:

1. cp /usr/share/doc/audit/rules/10-base-config.rules /usr/share/doc/audit/rules/30-stig.rules /usr/share/doc/audit/rules/31-privileged.rules /usr/share/doc/audit/rules/99-finalize.rules /etc/audit/rules.d/

2. augenrules --load'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50267r768167_chk'
  tag severity: 'medium'
  tag gid: 'V-246835'
  tag rid: 'SV-246835r768169_rule'
  tag stig_id: 'HYCU-AU-000009'
  tag gtitle: 'SRG-APP-000096-NDM-000226'
  tag fix_id: 'F-50221r768168_fix'
  tag satisfies: ['SRG-APP-000096-NDM-000226', 'SRG-APP-000097-NDM-000227', 'SRG-APP-000098-NDM-000228', 'SRG-APP-000099-NDM-000229', 'SRG-APP-000100-NDM-000230']
  tag 'documentable'
  tag cci: ['CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134']
  tag nist: ['AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e']
end
