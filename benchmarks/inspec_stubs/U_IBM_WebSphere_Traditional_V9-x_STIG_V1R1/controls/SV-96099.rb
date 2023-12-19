control 'SV-96099' do
  title 'The WebSphere Application Server high availability applications must be installed on a cluster.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards. These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

There are many examples of technologies that exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the application opens at one time). Employing increased capacity and bandwidth, combined with service redundancy or clustering, may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Review Systems Security Plan and identify system categorization.

If the system is not categorized as HIGH, this requirement is NA.

Identify HA applications installed on the server.

Verify applications defined as requiring HA protections are running on a cluster. 

From the admin console, navigate to Application >> All Applications >> [application name] >> Target specific application status.

If the target application has been designated as an HA application but is not running on a cluster, this is a finding.'
  desc 'fix', 'To create a cluster, navigate to Servers >> Clusters >> WebSphere Application Server Clusters >> New and follow the wizard.

After cluster creation, re-install your application to the cluster.

Refer to product documentation for specific details on how to create and manage WebSphere clusters.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81095r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81385'
  tag rid: 'SV-96099r1_rule'
  tag stig_id: 'WBSP-AS-001570'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-88171r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
