control 'SV-221936' do
  title 'Splunk Enterprise forwarders must be configured with Indexer Acknowledgement enabled.'
  desc 'To prevent the loss of data during transmission, a handshake acknowledgement between the sender and the recipient may need configured.'
  desc 'check', 'If the server being reviewed is not a forwarder, this check is N/A.

In the Splunk installation folder, check the following file in the $SPLUNK_HOME/etc/system/local folder:

outputs.conf

Locate the section similar to: 

[tcpout:group1]
useACK=true

Note that group1 may be named differently depending on how tcpout was configured.

If the useACK=true statement is missing or set to false, this is a finding.'
  desc 'fix', 'If the server is not a forwarder, this check is N/A.

In the Splunk installation folder, edit the following file in the $SPLUNK_HOME/etc/system/local folder:

outputs.conf

Locate the section similar to: 

[tcpout:group1]

Note that group1 may be named differently depending on how tcpout was configured.

Add the following line under the group stanza above:

useACK=true'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23650r420276_chk'
  tag severity: 'low'
  tag gid: 'V-221936'
  tag rid: 'SV-221936r879887_rule'
  tag stig_id: 'SPLK-CL-000175'
  tag gtitle: 'SRG-APP-000516-AU-000340'
  tag fix_id: 'F-23639r420277_fix'
  tag 'documentable'
  tag legacy: ['SV-111327', 'V-102377']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
