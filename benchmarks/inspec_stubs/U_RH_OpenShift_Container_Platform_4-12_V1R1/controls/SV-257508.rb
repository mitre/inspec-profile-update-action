control 'SV-257508' do
  title 'The kubeadmin account must be disabled.'
  desc 'Using a centralized user management solution for account management functions enhances security, simplifies administration, improves user experience, facilitates compliance, and provides scalability and integration capabilities. It is a foundational element of effective identity and access management practices.

OpenShift supports several different types of identity providers. To add users and grant access to OpenShift, an identity provider needs to be configured. Some of the identity provider types, such as HTPassword, only provide simple user management and are not intended for production. Other types are public services, like GitHub. These provider types may not be appropriate as they are managed by public service providers and therefore are unable to enforce the organizations account management requirements.

After a new install, the default authentication uses kubeadmin as the default cluster-admin account. This default account must be disabled and another user account must be given cluster-admin rights.'
  desc 'check', 'Verify the kubeadmin account is disabled by executing the following:

oc get secrets kubeadmin -n kube-system

If the command returns an error, the secret was not found, and this is not a finding.

(Example output:
Error from server (NotFound): secrets "kubeadmin" not found)

If the command returns a listing that includes the kubeadmin secret, its type, the data count, and age, this is a finding.

(Example Output for not a finding: 
NAME        TYPE     DATA   AGE
kubeadmin   Opaque   1      6h3m)'
  desc 'fix', 'If an alternative IDP is already configured and an administrative user exists with the role of cluster-admin, disable the kubeadmin account by running the following command as a cluster administrator:

oc delete secrets kubeadmin -n kube-system'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61243r921465_chk'
  tag severity: 'medium'
  tag gid: 'V-257508'
  tag rid: 'SV-257508r921467_rule'
  tag stig_id: 'CNTR-OS-000040'
  tag gtitle: 'SRG-APP-000023-CTR-000055'
  tag fix_id: 'F-61167r921466_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
