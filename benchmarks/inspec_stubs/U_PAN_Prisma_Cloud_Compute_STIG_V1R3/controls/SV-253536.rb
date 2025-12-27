control 'SV-253536' do
  title 'Prisma Cloud Compute Console must run as nonroot user (uid 2674).'
  desc 'Containers not requiring root-level permissions must run as a unique user account. To ensure accountability and prevent unauthenticated access to containers, the user the container is using to execute must be uniquely identified and authenticated to prevent potential misuse and compromise of the system.'
  desc 'check', 'Locate the node in which the Prisma Cloud Compute Console container is running. 

Determine the process owner for "app/server".

Execute: "ps -aux | grep "/app/server"

If the process is owned by root, this is a finding.'
  desc 'fix', "In the root directory of the extracted release tar file, modify the twistlock.cfg file's line:
RUN_CONSOLE_AS_ROOT=false

For Kubernetes deployment, perform these additional steps:

When generating the twistlock_console.yaml deployment file, supply the --run-as-user flag.

Linux/twistcli console export kubernetes --service-type ClusterIP --run-as-user 2674

Modify the resulting twistlock_console.yaml file to include fsGroup: 2674 within the Deployment pod specification's securityContext:
securityContext: fsGroup: 2674

Add runAsGroup: 2674 to the container specification's securityContext:
securityContext: runAsUser: 2674
runAsGroup: 2674"
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56988r840444_chk'
  tag severity: 'medium'
  tag gid: 'V-253536'
  tag rid: 'SV-253536r879589_rule'
  tag stig_id: 'CNTR-PC-000530'
  tag gtitle: 'SRG-APP-000148-CTR-000345'
  tag fix_id: 'F-56939r840445_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
