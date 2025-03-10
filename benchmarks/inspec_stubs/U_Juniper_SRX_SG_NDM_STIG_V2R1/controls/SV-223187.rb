control 'SV-223187' do
  title 'The Juniper SRX Services Gateway must generate a log event when privileged commands are executed.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.

All commands executed on the Juniper SRX are privileged commands. Thus, this requirement is configured using the same syslog command as CCI-000172.'
  desc 'check', 'Verify the device generates a log event when privileged commands are executed.

[edit] 
show system syslog

If a valid syslog host server and the syslog file names are not configured to capture "any" facility and "any" event, this is a finding.'
  desc 'fix', 'Along with the other commands that constitute a complete DoD syslog configuration, the following command must be ensure privileged commands are sent to the Syslog Server. 

[edit]
set system syslog host <IP-syslog-server> any any'
  impact 0.3
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24860r513254_chk'
  tag severity: 'low'
  tag gid: 'V-223187'
  tag rid: 'SV-223187r513256_rule'
  tag stig_id: 'JUSX-DM-000029'
  tag gtitle: 'SRG-APP-000343-NDM-000289'
  tag fix_id: 'F-24848r513255_fix'
  tag 'documentable'
  tag legacy: ['SV-81041', 'V-66551']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
