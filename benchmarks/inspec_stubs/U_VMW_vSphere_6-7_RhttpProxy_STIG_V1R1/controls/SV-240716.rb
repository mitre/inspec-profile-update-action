control 'SV-240716' do
  title 'The rhttpproxy must drop connections to disconnected clients.'
  desc 'The rhttpproxy client connections that are established but no longer connected can consume resources that might otherwise be required by active connections. It is a best practice to terminate connections that are no longer connected to an active client.'
  desc 'check', "At the command prompt, execute the following command:

# xmllint --xpath '/config/vmacore/tcpKeepAlive/clientSocket/idleTimeSec' /etc/vmware-rhttpproxy/config.xml

Expected result:

<idleTimeSec>900</idleTimeSec>

If the output does not match the expected result, this is a finding."
  desc 'fix', 'Navigate to and open /etc/vmware-rhttpproxy/config.xml.

Locate the <config>/<vmacore>/<tcpKeepAlive>/<clientSocket> block and configure <idleTimeSec> as follows:

<idleTimeSec>900</idleTimeSec>

Restart the service for changes to take effect.

# vmon-cli --restart rhttpproxy'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 RhttpProxy'
  tag check_id: 'C-43949r679659_chk'
  tag severity: 'medium'
  tag gid: 'V-240716'
  tag rid: 'SV-240716r679661_rule'
  tag stig_id: 'VCRP-67-000001'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-43908r679660_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
