control 'SV-246838' do
  title 'The HYCU server must initiate session auditing upon startup and produce audit log records containing sufficient information to establish what type of event occurred.'
  desc 'It is essential for security personnel to know what is being done, what was attempted, where it was done, when it was done, and by whom it was done in order to compile an accurate risk assessment. Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network device. Without this capability, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack. If auditing is enabled late in the startup process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.

'
  desc 'check', 'The Grizzly logs and Web UI events capture these activities.

Log on to the VM console and run the following command:
chkconfig auditd 

If the Audit Service is not in a running state, this is a finding. 

Check the contents of the "/var/log/audit/audit.log" file.
 
If the audit log does not have the required contents, this is a finding.'
  desc 'fix', 'Audit logging is enabled by default within the HYCU VM console. If an administrator disabled it, reenable it by logging on to the HYCU VM console and running the following command:
chkconfig auditd on

Use the following command to review the logs:
cat /var/log/secure | less  

Use the "/" character to search the log or timeframe for any undesired/unapproved changes.

Log on to the HYCU VM console and load the STIG audit rules by using the following commands: 

1. sudo cp /usr/share/audit/sample-rules/10-base-config.rules /usr/share/audit/sample-rules/30-stig.rules /usr/share/audit/sample-rules/31-privileged.rules /usr/share/audit/sample-rules/99-finalize.rules /etc/audit/rules.d/

2. sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50270r768176_chk'
  tag severity: 'medium'
  tag gid: 'V-246838'
  tag rid: 'SV-246838r768178_rule'
  tag stig_id: 'HYCU-AU-000015'
  tag gtitle: 'SRG-APP-000095-NDM-000225'
  tag fix_id: 'F-50224r768177_fix'
  tag satisfies: ['SRG-APP-000095-NDM-000225', 'SRG-APP-000319-NDM-000283', 'SRG-APP-000353-NDM-000292', 'SRG-APP-000495-NDM-000318', 'SRG-APP-000499-NDM-000319', 'SRG-APP-000503-NDM-000320', 'SRG-APP-000504-NDM-000321', 'SRG-APP-000505-NDM-000322', 'SRG-APP-000092-NDM-000224']
  tag 'documentable'
  tag cci: ['CCI-000018', 'CCI-000130', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-001464', 'CCI-001914', 'CCI-002130']
  tag nist: ['AC-2 (4)', 'AU-3 a', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AU-14 (1)', 'AU-12 (3)', 'AC-2 (4)']
end
