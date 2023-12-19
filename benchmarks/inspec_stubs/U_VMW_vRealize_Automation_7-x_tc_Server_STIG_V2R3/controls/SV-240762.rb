control 'SV-240762' do
  title 'tc Server VCO must be configured with the RemoteIpValve in order to produce log records containing the client IP information as the source and destination and not the load balancer or proxy IP information with each event.'
  desc 'tc Server HORIZON logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined. 

Ascertaining the correct source, e.g. source IP, of the events is important during forensic analysis. Correctly determining the source of events will add information to the overall reconstruction of the logable event. By determining the source of the event correctly, analysis of the enterprise can be undertaken to determine if events tied to the source occurred in other areas within the enterprise.

tc Server HORIZON must be configured with the RemoteIpValve element in order to record the Client source vice the load balancer or proxy server as the source of every logable event. The RemoteIpValve enables the x-forward-* HTTP properties, which are used by the load balance to provide the client source.'
  desc 'check', 'At the command prompt, execute the following command:

tail /storage/log/vmware/vco/app-server/localhost_access_log.txt

If actual client IP information, not load balancer or proxy server, is not being recorded, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/vco/app-server/server.xml.

Navigate to and locate <Host>.

Configure the <Host> node with the <RemoteIpValve> below.

Note: The "RemoteIpValve" should be configured as follows:
                <Valve className="org.apache.catalina.valves.RemoteIpValve"
                       remoteIpHeader="x-forwarded-for"
                       remoteIpProxiesHeader="x-forwarded-by"
                       internalProxies=".*"
                       protocolHeader="x-forwarded-proto" />'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-43995r674028_chk'
  tag severity: 'medium'
  tag gid: 'V-240762'
  tag rid: 'SV-240762r879566_rule'
  tag stig_id: 'VRAU-TC-000210'
  tag gtitle: 'SRG-APP-000098-WSR-000060'
  tag fix_id: 'F-43954r674029_fix'
  tag 'documentable'
  tag legacy: ['SV-100609', 'V-89959']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
