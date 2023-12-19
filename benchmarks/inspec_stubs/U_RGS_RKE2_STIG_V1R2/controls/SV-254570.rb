control 'SV-254570' do
  title 'Rancher RKE2 runtime must maintain separate execution domains for each container by assigning each container a separate address space to prevent unauthorized and unintended information transfer via shared system resources.'
  desc 'Separating user functionality from management functionality is a requirement for all the components within the Kubernetes Control Plane. Without the separation, users may have access to management functions that can degrade the Kubernetes architecture and the services being offered, and can offer a method to bypass testing and validation of functions before introduced into a production environment.

'
  desc 'check', 'System namespaces are reserved and isolated.

To view the available namespaces, run the command: 
kubectl get namespaces

The namespaces to be validated include:
default
kube-public
kube-system
kube-node-lease

For the default namespace, execute the commands:
kubectl config set-context --current --namespace=default 
kubectl get all 

For the kube-public namespace, execute the commands:
kubectl config set-context --current --namespace=kube-public
kubectl get all                                                                                                                                                                                                                                                                                                                                        
                                                                                                                                                                                                                                                                                                                                                       
For the kube-node-lease namespace, execute the commands:
kubectl config set-context --current --namespace=kube-node-lease
kubectl get all                                                                                                                                                                                                                                                                                                                                        
                                                                                                                                                                                                                                                                                                                                                       
The only return values are the Kubernetes service objects (e.g., service/kubernetes).
                                                                                                                            
For the kube-system namespace, execute the commands:
kubectl config set-context --current --namespace=kube-system                                                                                                                                                                                                                                                                                           
kubectl get all 

The values returned include the following resources:                                                                                                                                                                                                                                                                           
- ETCD                                                                                                                                                                                                                                                                                                                                                 
- Helm
- Kubernetes API Server
- Kubernetes Controller Manager 
- Kubernetes Proxy
- Kubernetes Scheduler 
- Kubernetes Networking Components
- Ingress Controller Components 
- Metrics Server

If a return value from the "kubectl get all" command is not the Kubernetes service or one from the above lists, this is a finding.'
  desc 'fix', 'System namespaces are reserved and isolated.

A resource cannot move to a new namespace; the resource must be deleted and recreated in the new namespace.

kubectl delete <resource_type> <resource_name>
kubectl create -f <resource.yaml> --namespace=<user_created_namespace>'
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58054r870259_chk'
  tag severity: 'medium'
  tag gid: 'V-254570'
  tag rid: 'SV-254570r879649_rule'
  tag stig_id: 'CNTR-R2-000970'
  tag gtitle: 'SRG-APP-000243-CTR-000600'
  tag fix_id: 'F-58003r870260_fix'
  tag satisfies: ['SRG-APP-000243-CTR-000600', 'SRG-APP-000431-CTR-001065', 'SRG-APP-000211-CTR-000530', 'SRG-APP-000243-CTR-000595']
  tag 'documentable'
  tag cci: ['CCI-001082', 'CCI-001090', 'CCI-002530']
  tag nist: ['SC-2', 'SC-4', 'SC-39']
end
