control 'SV-79629' do
  title 'The DataPower Gateway must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', %q(Using the WebGUI, go to Objects >> Logging Configuration >> Audit Log Settings. Confirm that the Administrative state is "enabled" and that the status displayed alongside the "Audit Log Settings" heading is "[up]".

As a final test, execute a privileged function and confirm that an entry appears in the audit log. Using the WebGUI, go to Administration >> Access >> New User Account. Click "No". Select "Developer". Click Next. Enter "TestDeveloper" as the name and enter a password. Click Next. Click Commit. Click Done.

Now view the Audit log by using the WebGUI to got to Status >> View Logs >> Audit Log. Scroll to the bottom of the log and confirm that you see the following entry: "user 'TestDeveloper' - Configuration added". 

If this event message does not appear in the audit log, this is a finding.)
  desc 'fix', 'The DataPower device logs the execution of all privileged functions.

The DataPower Audit log is enabled by default. To configure this log, go to the WebGUI at Objects >> Logging Configuration >> Audit Log Settings. Set the Administrative state to "enable". Specify the desired Log Size, Number of Rotations. Set the Audit Level to "full" (the default setting). The result of this configuration must be that the status displayed alongside the "Audit Log Settings" heading is "[up]".'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65767r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65139'
  tag rid: 'SV-79629r1_rule'
  tag stig_id: 'WSDP-NM-000091'
  tag gtitle: 'SRG-APP-000343-NDM-000289'
  tag fix_id: 'F-71079r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
