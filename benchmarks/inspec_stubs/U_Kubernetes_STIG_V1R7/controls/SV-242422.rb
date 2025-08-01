control 'SV-242422' do
  title 'Kubernetes API Server must have a certificate for communication.'
  desc 'Kubernetes control plane and external communication is managed by API Server. The main implementation of the API Server is to manage hardware resources for pods and container using horizontal or vertical scaling. Anyone who can access the API Server can effectively control the Kubernetes architecture. Using authenticity protection, the communication can be protected against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

The communication session is protected by utilizing transport encryption protocols, such as TLS. TLS provides the Kubernetes API Server with a means to be able to authenticate sessions and encrypt traffic. 

To enable encrypted communication for API Server, the parameter etcd-cafile must be set. This parameter gives the location of the SSL Certificate Authority file used to secure API Server communication.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i tls-cert-file *
grep -i tls-private-key-file *

If the setting tls-cert-file and private-key-file is not set in the Kubernetes API server manifest file or contains no value, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of tls-cert-file and tls-private-key-file to path containing Approved Organizational Certificate.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45697r863854_chk'
  tag severity: 'medium'
  tag gid: 'V-242422'
  tag rid: 'SV-242422r863997_rule'
  tag stig_id: 'CNTR-K8-001440'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag fix_id: 'F-45655r863855_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
