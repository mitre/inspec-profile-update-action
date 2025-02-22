control 'SV-240763' do
  title 'tc Server VCAC must be configured with the RemoteIpValve in order to produce log records containing the client IP information as the source and destination and not the load balancer or proxy IP information with each event.'
  desc 'tc Server VCAC logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined. 

Ascertaining the correct source, e.g. source IP, of the events is important during forensic analysis. Correctly determining the source of events will add information to the overall reconstruction of the logable event. By determining the source of the event correctly, analysis of the enterprise can be undertaken to determine if events tied to the source occurred in other areas within the enterprise.

tc Server VCAC must be configured with the RemoteIpValve element in order to record the Client source vice the load balancer or proxy server as the source of every logable event. The RemoteIpValve enables the x-forward-* HTTP properties, which are used by the load balance to provide the client source.'
  desc 'check', 'At the command prompt, execute the following command:

tail /storage/log/vmware/vcac/access_log.YYYY-MM-dd.txt

Note: Substitute the actual date in the file name.

If actual client IP information, not load balancer or proxy server, is not being recorded, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/vcac/server.xml.

Navigate to and locate <Host>.

Configure the <Host> node with the <RemoteIpValve> below.

Note: The "RemoteIpValve" should be configured as follows:
                <Valve className="org.apache.catalina.valves.RemoteIpValve"
                        httpServerPort="80"
                        httpsServerPort="443" 
                        internalProxies="127\\.0\\.0\\.1"
                        protocolHeader="x-forwarded-proto"
                        proxiesHeader="x-forwarded-by"
                        remoteIpHeader="x-forwarded-for"/>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-43996r674413_chk'
  tag severity: 'medium'
  tag gid: 'V-240763'
  tag rid: 'SV-240763r674414_rule'
  tag stig_id: 'VRAU-TC-000215'
  tag gtitle: 'SRG-APP-000098-WSR-000060'
  tag fix_id: 'F-43955r674032_fix'
  tag 'documentable'
  tag legacy: ['SV-100611', 'V-89961']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
