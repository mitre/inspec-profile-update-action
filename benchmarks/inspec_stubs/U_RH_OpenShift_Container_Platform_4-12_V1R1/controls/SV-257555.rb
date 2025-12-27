control 'SV-257555' do
  title 'OpenShift must restrict individuals the ability to launch organizational-defined Denial-of-Service (DOS) attacks against other information systems by rate-limiting.'
  desc 'By setting rate limits, OpenShift can control the number of requests or connections allowed from a single source within a specific period. This prevents an excessive influx of requests that can overwhelm the application and degrade its performance or availability.

Setting rate limits also ensures fair resource allocation, prevents service degradation, protects backend systems, and enhances overall security. Along with, helping to maintain the availability, performance, and security of the applications hosted on the platform, contributing to a reliable and robust application infrastructure.

OpenShift has an option to set the rate limit for Routes (refer to link below) when creating new Routes. All routes outside the OpenShift namespaces and the kube namespaces must use the rate-limiting annotations.

https://docs.openshift.com/container-platform/4.9/networking/routes/route-configuration.html#nw-route-specific-annotations_route-configuration'
  desc 'check', %q(Verify that all namespaces except those that start with kube-* or openshift-* use the rate-limiting annotation by executing the following:

oc get routes --all-namespaces -o json | jq '[.items[] | select(.metadata.namespace | startswith("kube-") or startswith("openshift-") | not) | select(.metadata.annotations["haproxy.router.openshift.io/rate-limit-connections"] == "true" | not) | .metadata.name]'

If the above command returns any namespaces, this is a finding.)
  desc 'fix', 'Add the haproxy.router.openshift.io/rate-limit-connections annotation to any routes outside the kube-* or openshift-* namespaces 

oc annotate route <route_name> -n <namespace> --overwrite=true "haproxy.router.openshift.io/timeout=2s"

https://docs.openshift.com/container-platform/4.9/networking/routes/route-configuration.html'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61290r921606_chk'
  tag severity: 'medium'
  tag gid: 'V-257555'
  tag rid: 'SV-257555r921608_rule'
  tag stig_id: 'CNTR-OS-000630'
  tag gtitle: 'SRG-APP-000246-CTR-000605'
  tag fix_id: 'F-61214r921607_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
