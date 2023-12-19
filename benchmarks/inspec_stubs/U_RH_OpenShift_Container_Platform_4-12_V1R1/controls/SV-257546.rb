control 'SV-257546' do
  title 'OpenShift must protect authenticity of communications sessions with the use of FIPS-validated 140-2 or 140-3 validated cryptography.'
  desc 'FIPS compliance is one of the most critical components required in highly secure environments, to ensure that only supported cryptographic technologies are allowed on nodes.

Because FIPS must be enabled before the operating system used by the cluster boots for the first time, FIPS cannot be disabled after a cluster is deployed.

OpenShift employs industry-validated cryptographic algorithms, key management practices, and secure protocols, reducing the likelihood of cryptographic vulnerabilities and attacks.

'
  desc 'check', %q(To validate the OpenShift cluster is running with FIPS enabled on each node by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; sysctl crypto.fips_enabled' 2>/dev/null; done

If any lines of output end in anything other than 1, this is a finding.)
  desc 'fix', %q(Reinstall the OpenShift cluster in FIPS mode. The file install-config.yaml has a top-level key that enables FIPS mode for all nodes and the cluster platform layer. If the install-config.yaml was not backed up prior to consumption as part of the installation, recreate it. An example install-config.yaml with some sections trimmed out for brevity, and the "fips: true" key applied at the top level is shown below:

apiVersion: v1
baseDomain: example.com
controlPlane:
  name: master
  platform:
    aws:
      [...]
  replicas: 3
compute:
- name: worker
  platform:
    aws:
  replicas: 3
metadata:
  name: fips-cluster
networking:
  [...]
platform:
  aws:
    [...]
sshKey: ssh-ed25519 AAAA...
pullSecret: '{"auths": ...}'
fips: true

Once the install-config.yaml is saved with corresponding correct information for the installation infrastructure, run the installer to create a cluster that uses FIPS Validated/Modules in Process cryptographic libraries. The command to install a cluster and consume the install-config.yaml is:
> ./openshift-install create cluster --dir=<installation_directory> --log-level=info
Where <installation_directory> is the directory that contains install-config.yaml

Additional details can be found here: https://docs.openshift.com/container-platform/4.8/installing/installing-fips.html)
  impact 0.7
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61281r921579_chk'
  tag severity: 'high'
  tag gid: 'V-257546'
  tag rid: 'SV-257546r921581_rule'
  tag stig_id: 'CNTR-OS-000510'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag fix_id: 'F-61205r921580_fix'
  tag satisfies: ['SRG-APP-000219-CTR-000550', 'SRG-APP-000635-CTR-001405', 'SRG-APP-000126-CTR-000275', 'SRG-APP-000411-CTR-000995', 'SRG-APP-000412-CTR-001000', 'SRG-APP-000416-CTR-001015', 'SRG-APP-000514-CTR-001315']
  tag 'documentable'
  tag cci: ['CCI-001184', 'CCI-001350', 'CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['SC-23', 'AU-9 (3)', 'SC-13 b', 'MA-4 (6)', 'MA-4 (6)']
end
