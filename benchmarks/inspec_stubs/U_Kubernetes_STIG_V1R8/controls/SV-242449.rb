control 'SV-242449' do
  title 'The Kubernetes Kubelet certificate authority file must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes kubelet certificate authority file contains settings for the Kubernetes Node TLS certificate authority. Any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate. If this file can be changed, the Kubernetes architecture could be compromised. The scheduler will implement the changes immediately. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'Change to the /etc/sysconfig/ directory on the Kubernetes Control Plane. Run command:
more kubelet
--client-ca-file argument 
Note certificate location

If the ca-file argument location file has permissions more permissive than "644", this is a finding.'
  desc 'fix', 'Change the permissions of the --client-ca-file to "644" by executing the command:

chmod 644 <kubelet --client--ca-file argument location>.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45724r863915_chk'
  tag severity: 'medium'
  tag gid: 'V-242449'
  tag rid: 'SV-242449r864021_rule'
  tag stig_id: 'CNTR-K8-003160'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45682r821613_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
