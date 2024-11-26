control 'SV-246834' do
  title 'The HYCU server must generate audit records for privileged activities or other system-level access.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).

'
  desc 'check', 'Log on to the VM console and run the following command:
chkconfig auditd 

If the Audit Service is not in a running state, this is a finding. 

Also, if no logs are present in the "/var/log/secure directory", this is a finding.'
  desc 'fix', 'Audit logging is enabled by default within the HYCU VM console. If an administrator disabled it, reenable it by logging on to the HYCU VM console and running the following command:
chkconfig auditd on

Use the following command to review the logs:
cat /var/log/secure | less 

Use the "/" character to search the log or timeframe for any undesired/unapproved changes.'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50266r768164_chk'
  tag severity: 'medium'
  tag gid: 'V-246834'
  tag rid: 'SV-246834r768166_rule'
  tag stig_id: 'HYCU-AU-000006'
  tag gtitle: 'SRG-APP-000504-NDM-000321'
  tag fix_id: 'F-50220r768165_fix'
  tag satisfies: ['SRG-APP-000504-NDM-000321', 'SRG-APP-000506-NDM-000323', 'SRG-APP-000516-NDM-000334']
  tag 'documentable'
  tag cci: ['CCI-000169', 'CCI-000172', 'CCI-000366']
  tag nist: ['AU-12 a', 'AU-12 c', 'CM-6 b']
end
