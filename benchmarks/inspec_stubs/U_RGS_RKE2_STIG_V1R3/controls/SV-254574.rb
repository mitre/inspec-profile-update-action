control 'SV-254574' do
  title 'Rancher RKE2 must remove old components after updated versions have been installed.'
  desc 'Previous versions of Rancher RKE2 components that are not removed after updates have been installed may be exploited by adversaries by causing older components to execute which contain vulnerabilities. When these components are deleted, the likelihood of this happening is removed.'
  desc 'check', %q(To view all pods and the images used to create the pods, from the RKE2 Control Plane, run the following command:

kubectl get pods --all-namespaces -o jsonpath="{..image}" | \
tr -s '[[:space:]]' '\n' | \
sort | \
uniq -c

Review the images used for pods running within Kubernetes.
If there are multiple versions of the same image, this is a finding.)
  desc 'fix', 'Remove any old pods that are using older images. On the RKE2 Control Plane, run the command:

kubectl delete pod podname
(Note: "podname" is the name of the pod to delete.)

Run the command:
systemctl restart rke2-server'
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58058r859290_chk'
  tag severity: 'medium'
  tag gid: 'V-254574'
  tag rid: 'SV-254574r879825_rule'
  tag stig_id: 'CNTR-R2-001580'
  tag gtitle: 'SRG-APP-000454-CTR-001110'
  tag fix_id: 'F-58007r859291_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
