control 'SV-253534' do
  title 'Prisma Cloud Compute must use TCP ports above 1024.'
  desc 'Privileged ports are ports below 1024 that require system privileges for their use. If containers are able to use these ports, the container must be run as a privileged user. The container platform must stop containers that try to map to these ports directly. Allowing nonprivileged ports to be mapped to the container-privileged port is the allowable method when a certain port is needed. Prisma Cloud Compute default TCP ports are 8083 (Console UI and API) and 8084 (Console-to-Defender communication). To use TCP ports below 1024, the Console would have to be configured to use privileged ports.'
  desc 'check', "For Kubernetes deployment:

Query the ports used by the twistlock-console service:
$ kubectl describe svc twistlock-console -n twistlock

If any port number is below 1024, this is a finding.

For Docker deployment:

Determine the name of the Console container:
docker ps|grep console

For example, the Console container is: ad8b41a2fec9 
ad8b41a2fec9
twistlock/private:console_22_01_840

Inspect the container's PortBindings:
docker inspect ad8b41a2fec9|grep PortBindings -A 20

If the port is below 1024, this is a finding."
  desc 'fix', 'For Kubernetes deployment:

Edit the deployment.apps/twistlock-console.

Find the - name: TargetPorts below 1024.

Change to port number above 1024.

Save and exit the editing session. The Console will restart automatically.

For Docker deployment:

Modify the twistlock.cfg located in the extracted release tar directory.

Change any port assignment below 1024 to above 1024:
MANAGEMENT_PORT_HTTP=
MANAGEMENT_PORT_HTTPS=8083
COMMUNICATION_PORT=8084

Redeploy the Console using the twistlock.sh script in the extracted release tar directory:
$ sudo ./twisltock.sh -sy onebox'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56986r840438_chk'
  tag severity: 'medium'
  tag gid: 'V-253534'
  tag rid: 'SV-253534r879588_rule'
  tag stig_id: 'CNTR-PC-000500'
  tag gtitle: 'SRG-APP-000142-CTR-000330'
  tag fix_id: 'F-56937r840439_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
