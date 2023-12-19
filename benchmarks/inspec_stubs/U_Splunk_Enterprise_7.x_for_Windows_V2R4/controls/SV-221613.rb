control 'SV-221613' do
  title 'Splunk Enterprise must be configured to protect the log data stored in the indexes from alteration.'
  desc 'Without non-repudiation, it is impossible to positively attribute an action to an individual (or process acting on behalf of an individual).

The records stored by Splunk Enterprise must be protected against alteration. A hash is one way of performing this function. The server must not allow the removal of identifiers or date/time, or it must severely restrict the ability to do so.'
  desc 'check', 'If the server being reviewed does not store index data, this check is N/A.

Check the following file in the installation folder:

$SPLUNK_HOME/etc/system/local/indexes.conf

Verify that each organization-defined index stanza in brackets [ ] has the following line added:

enableDataIntegrityControl=true

If this line is missing or is set to false, this is a finding.'
  desc 'fix', 'If the server does not store index data, this fix is N/A.

Edit the following file in the installation folder:

$SPLUNK_HOME/etc/system/local/indexes.conf

Add the following line to each organization-defined index stanza in brackets [ ]:

enableDataIntegrityControl=true'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23328r416296_chk'
  tag severity: 'medium'
  tag gid: 'V-221613'
  tag rid: 'SV-221613r879554_rule'
  tag stig_id: 'SPLK-CL-000160'
  tag gtitle: 'SRG-APP-000080-AU-000010'
  tag fix_id: 'F-23317r416297_fix'
  tag 'documentable'
  tag legacy: ['SV-111323', 'V-102373']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
