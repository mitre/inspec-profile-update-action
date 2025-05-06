control 'SV-251662' do
  title 'Splunk Enterprise must be configured to protect the log data stored in the indexes from alteration.'
  desc 'Without non-repudiation, it is impossible to positively attribute an action to an individual (or process acting on behalf of an individual).

The records stored by Splunk Enterprise must be protected against alteration. A hash is one way of performing this function. The server must not allow the removal of identifiers or date/time, or it must severely restrict the ability to do so.'
  desc 'check', 'This check is performed on the machine used as an indexer, which may be a separate machine in a distributed environment.

If the instance being reviewed is not used as an indexer, this check is N/A.

Examine the configuration.

Navigate to the $SPLUNK_HOME/etc/system/local/ directory. View the indexes.conf file.
 
If the indexes.conf file does not exist, this is a finding.

If the "enableDataIntegrityControl" is missing or is configured to 0 or false for each index, this is a finding.'
  desc 'fix', 'If the indexes.conf file does not exist, copy the file from $SPLUNK_HOME/etc/system/default to the $SPLUNK_HOME/etc/system/local directory.

Modify the following lines in the indexes.conf file under each index:

enableDataIntegrityControl = 1 or True'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55100r835281_chk'
  tag severity: 'medium'
  tag gid: 'V-251662'
  tag rid: 'SV-251662r879554_rule'
  tag stig_id: 'SPLK-CL-000090'
  tag gtitle: 'SRG-APP-000080-AU-000010'
  tag fix_id: 'F-55054r835282_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
