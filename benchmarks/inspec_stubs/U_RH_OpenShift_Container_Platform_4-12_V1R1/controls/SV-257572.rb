control 'SV-257572' do
  title 'OpenShift runtime must have updates installed within the period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'OpenShift runtime must be carefully monitored for vulnerabilities, and when problems are detected, they must be remediated quickly. A vulnerable runtime exposes all containers it supports, as well as the host itself, to potentially significant risk. Organizations must use tools to look for Common Vulnerabilities and Exposures (CVEs) in the runtimes deployed, to upgrade any instances at risk, and to ensure that orchestrators only allow deployments to properly maintained runtimes.

'
  desc 'check', %q(To list all the imagestreams and identify which imagestream tags are configured to periodically check for updates (imagePolicy = { scheduled: true }), execute the following:

oc get imagestream  --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{range .spec.tags[*]}{"\t"}{.name}{": "}{.importPolicy}{"\n"}'

The output will be similar to:

httpd
        2.4: {}
        2.4-el7: {}
        2.4-el8: {}
        latest: {}
        : 
installer
        latest: {"scheduled":true}
        : 
installer-artifacts
        latest: {"scheduled":true}
        : 

Review the listing, and for each imagestream tag version that does not have the value '{"scheduled":true}' that should otherwise check for updates, this is a finding.)
  desc 'fix', %q(For container images that are not scheduled to check for updates that otherwise should, update the imagestream to schedule updates for each tag by executing the following:

oc patch imagestream <NAME> -n NAMESPACE --type merge -p '{"spec":{"tags":[{"name":"<TAG_NAME>","importPolicy":{"scheduled":true}}]}}' 

where,
  NAME: The imagestream name to update
  NAMESPACE: The namespace the imagestream is in. This will most often be 'openshift'.
  TAG_NAME: The imagestream tag to update)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61307r921657_chk'
  tag severity: 'medium'
  tag gid: 'V-257572'
  tag rid: 'SV-257572r921659_rule'
  tag stig_id: 'CNTR-OS-000900'
  tag gtitle: 'SRG-APP-000456-CTR-001130'
  tag fix_id: 'F-61231r921658_fix'
  tag satisfies: ['SRG-APP-000456-CTR-001130', 'SRG-APP-000456-CTR-001125']
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
