control 'SV-253522' do
  title 'Prisma Cloud Compute Console must use TLS 1.2 for user interface and API access. Communication TCP ports must adhere to the Ports, Protocols, and Services Management Category Assurance Levels (PSSM CAL).'
  desc "Communication to Prisma Cloud Compute Console's User Interface (UI) and API is protected by TLS v1.2+ (HTTPS). By default, only HTTPS communication to the Console's UI and API endpoints is enabled.

Prisma Cloud Compute TCP port usage is configurable. 

Default configuration: TCP 8081 Console user interface and API (HTTP) - disabled by default. TCP 8083 Console user interface and API TLS v1.2 (HTTPS) TCP 8084 Console-to-Defender communication via mutual TLS v1.2 WebSocket session.

"
  desc 'check', "For Kubernetes deployment:

Query the ports used by the twistlock-console service:
$ kubectl describe svc twistlock-console -n twistlock

If the TargetPort management-port-http exists and has a port assignment, this is a finding.
Port: management-port-http  8081/TCP
TargetPort: 8081/TCP

For Docker deployment:

Determine the name of the Console container:
docker ps|grep console

For example, the Console container is: ad8b41a2fec9 
   twistlock/private:console_22_01_840

Inspect the container's PortBindings:
docker inspect ad8b41a2fec9|grep PortBindings -A 20

If port 8081 is listed, this is a finding."
  desc 'fix', 'For Kubernetes deployment:

Edit the deployment.apps/twistlock-console.

Find the - name: MANAGEMENT_PORT_HTTP setting

Remove the value assignment (e.g., 8081):
        - name: MANAGEMENT_PORT_HTTP
          value: "8081" 

Save and exit the editing session. The Console will restart automatically.

For Docker deployment:

Modify the twistlock.cfg located in the extracted release tar directory.

Remove the value assignment for the MANAGEMENT_PORT_HTTP= variable.

Redeploy the Console using the twistlock.sh script located in the extracted release tar directory.

$ sudo ./twisltock.sh -sy onebox'
  impact 0.7
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56974r840402_chk'
  tag severity: 'high'
  tag gid: 'V-253522'
  tag rid: 'SV-253522r879519_rule'
  tag stig_id: 'CNTR-PC-000020'
  tag gtitle: 'SRG-APP-000014-CTR-000040'
  tag fix_id: 'F-56925r840403_fix'
  tag satisfies: ['SRG-APP-000014-CTR-000040', 'SRG-APP-000142-CTR-000325', 'SRG-APP-000185-CTR-000490', 'SRG-APP-000645-CTR-001410']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000382', 'CCI-000877']
  tag nist: ['AC-17 (2)', 'CM-7 b', 'MA-4 c']
end
