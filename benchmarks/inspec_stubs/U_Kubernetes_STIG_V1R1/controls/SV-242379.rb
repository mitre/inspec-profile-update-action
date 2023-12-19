control 'SV-242379' do
  title 'The Kubernetes etcd must use TLS to protect the confidentiality of sensitive data during electronic dissemination.'
  desc 'Kubernetes etcd will prohibit the use of SSL and unauthorized versions of TLS protocols to properly secure communication.

The use of unsupported protocol exposes vulnerabilities to the Kubernetes by rogue traffic interceptions, man-in-the-middle attacks, and impersonation of users or services from the container platform runtime, registry, and keystore. To enable the minimum version of TLS to be used by the Kubernetes API Server, the setting "tls-min-version" must be set.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node. Run the command:

grep -i  auto-tls * 

If the setting "auto-tls" is not configured in the Kubernetes etcd manifest file or it is set to true, this is a finding.'
  desc 'fix', 'Edit the Kubernetes etcd manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the value of "-auto-tls" to "false".'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45654r712491_chk'
  tag severity: 'medium'
  tag gid: 'V-242379'
  tag rid: 'SV-242379r712493_rule'
  tag stig_id: 'CNTR-K8-000180'
  tag gtitle: 'SRG-APP-000014-CTR-000035'
  tag fix_id: 'F-45612r712492_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
