control 'SV-242427' do
  title 'Kubernetes etcd must have a key file for secure communication.'
  desc 'Kubernetes stores configuration and state information in a distributed key-value store called etcd. Anyone who can write to etcd can effectively control the Kubernetes cluster. Even just reading the contents of etcd could easily provide helpful hints to a would-be attacker. Using authenticity protection, the communication can be protected against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

The communication session is protected by utilizing transport encryption protocols, such as TLS. TLS provides the Kubernetes API Server and etcd with a means to be able to authenticate sessions and encrypt traffic. 

To enable encrypted communication for etcd, the parameter key-file must be set. This parameter gives the location of the key file used to secure etcd communication.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. 

Run the command:
    grep -i key-file *

If the setting "key-file" is not configured in the etcd manifest  file, this is a finding.'
  desc 'fix', 'Edit the Kubernetes etcd manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. 

Set the value of "--key-file" to the Approved Organizational Certificate.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45702r863869_chk'
  tag severity: 'medium'
  tag gid: 'V-242427'
  tag rid: 'SV-242427r864002_rule'
  tag stig_id: 'CNTR-K8-001490'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag fix_id: 'F-45660r863870_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
