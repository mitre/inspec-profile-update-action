control 'SV-240721' do
  title 'The rhttpproxy must have logging enabled.'
  desc 'After a security incident has occurred, investigators will often review log files to determine what happened. The rhttpproxy must create logs upon service startup to capture information relevant to investigations.'
  desc 'check', "At the command prompt, execute the following command:

# xmllint --xpath '/config/log/outputToFiles' /etc/vmware-rhttpproxy/config.xml

Expected result:

<outputToFiles>true</outputToFiles>

If the output does not match the expected result, this is a finding."
  desc 'fix', 'Navigate to and open /etc/vmware-rhttpproxy/config.xml.

Locate the <config>/<log> block and configure <outputToFiles> as follows:

<outputToFiles>true</outputToFiles>

Restart the service for changes to take effect.

# vmon-cli --restart rhttpproxy'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 RhttpProxy'
  tag check_id: 'C-43954r679674_chk'
  tag severity: 'medium'
  tag gid: 'V-240721'
  tag rid: 'SV-240721r879562_rule'
  tag stig_id: 'VCRP-67-000006'
  tag gtitle: 'SRG-APP-000092-WSR-000055'
  tag fix_id: 'F-43913r679675_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
