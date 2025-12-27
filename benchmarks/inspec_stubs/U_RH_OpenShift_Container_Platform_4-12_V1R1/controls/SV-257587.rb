control 'SV-257587' do
  title 'OpenShift must use FIPS-validated SHA-2 or higher hash function for digital signature generation and verification (nonlegacy use).'
  desc 'Using a FIPS-validated SHA-2 or higher hash function for digital signature generation and verification in OpenShift ensures strong cryptographic security, compliance with industry standards, and protection against known attacks. It promotes the integrity, authenticity, and nonrepudiation of digital signatures, which are essential for secure communication and data exchange in the OpenShift platform.

SHA1 is disabled in digital signatures when FIPS mode is enabled. OpenShift must verify that the certificates in /etc/kubernetes and /etc/pki are using sha256 signatures.'
  desc 'check', 'Verify the use of a FIPS-compliant hash function for digital signature generation and validation, by executing and reviewing the following commands:

update-crypto-policies --show

If the return is not "FIPS", this is a finding.

Verify the crypto-policies by executing the following:

openssl x509 -in /etc/kubernetes/kubelet-ca.crt -noout -text | grep Algorithm

openssl x509 -in /etc/kubernetes/ca.crt -noout -text | grep Algorithm

If any of the crypto-policies listed are not FIPS compliant, this is a finding. Details of algorithms can be reviewed at the following knowledge base article:
https://access.redhat.com/articles/3642912'
  desc 'fix', %q(Reinstall the OpenShift cluster in FIPS mode. The file install-config.yaml has a top-level key that enables FIPS mode for all nodes and the cluster platform layer. If the install-config.yaml was not backed up prior to consumption as part of the installation, it must be recreated. An example install-config.yaml with some sections trimmed out for brevity, and the "fips: true" key applied at the top level is shown below:

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

After saving the install-config.yaml with the corresponding correct information, run the installer to create a cluster that uses FIPS-validated Modules in Process cryptographic libraries. The command to install a cluster and consume the install-config.yaml is:

> ./openshift-install create cluster --dir=<installation_directory> --log-level=info
Where <installation_directory> is the directory that contains install-config.yaml

Additional details can be found here: https://docs.openshift.com/container-platform/4.8/installing/installing-fips.html)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61322r921702_chk'
  tag severity: 'medium'
  tag gid: 'V-257587'
  tag rid: 'SV-257587r921704_rule'
  tag stig_id: 'CNTR-OS-001080'
  tag gtitle: 'SRG-APP-000610-CTR-001385'
  tag fix_id: 'F-61246r921703_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
