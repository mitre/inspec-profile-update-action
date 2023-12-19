control 'SV-250328' do
  title 'The WebSphere Liberty Server must protect log information from unauthorized access or changes.'
  desc '<0> [object Object]'
  desc 'check', 'As a user with local file access to ${server.config.dir}/logs, verify the following audit log files have the correct file permissions of 660.

audit.log
messages.log
console.log
trace.log (if it exists)

If the file permissions for these files are not set to 660, this is a finding.'
  desc 'fix', 'As a user with local file access to ${server.config.dir}/logs, use the chmod command to configure the following log files to have the correct file permissions of 660.

chmod 660 <filename.log>

audit.log
messages.log
console.log
trace.log (if it exists)'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53763r795035_chk'
  tag severity: 'medium'
  tag gid: 'V-250328'
  tag rid: 'SV-250328r795037_rule'
  tag stig_id: 'IBMW-LS-000260'
  tag gtitle: 'SRG-APP-000119-AS-000079'
  tag fix_id: 'F-53717r795036_fix'
  tag cci: ['CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a']
end
