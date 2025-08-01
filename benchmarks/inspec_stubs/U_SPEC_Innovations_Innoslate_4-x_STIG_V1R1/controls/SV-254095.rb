control 'SV-254095' do
  title 'Innoslate must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.'
  desc 'check', '1. Access the logging.properties file in the logs directory of the Innoslate files.
2. Verify the  ____.apache.juli.AsyncFileHandler.directory field is set to a directory on a different system. Otherwise, this is a finding.'
  desc 'fix', '1. Access the logging.properties file in the logs directory of the Innoslate files.
2. Set the ____.apache.juli.AsyncFileHandler.directory fields to the directory or directories required.
3. Save.
4. Restart the service.'
  impact 0.5
  ref 'DPMS Target SPEC Innovations Innoslate 4.x'
  tag check_id: 'C-57580r845259_chk'
  tag severity: 'medium'
  tag gid: 'V-254095'
  tag rid: 'SV-254095r845261_rule'
  tag stig_id: 'SPEC-IN-000720'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-57531r845260_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
