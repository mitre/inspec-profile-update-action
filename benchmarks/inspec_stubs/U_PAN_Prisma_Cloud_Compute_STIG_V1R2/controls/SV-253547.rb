control 'SV-253547' do
  title 'Prisma Cloud Compute must run within a defined/separate namespace (e.g., Twistlock).'
  desc "Namespaces are a key boundary for network policies, orchestrator access control restrictions, and other important security controls. Prisma Cloud Compute containers running within a separate and exclusive namespace will inherit the namespace's security features. Separating workloads into namespaces can help contain attacks and limit the impact of mistakes or destructive actions by authorized users."
  desc 'check', 'Inspect the Kubernetes namespace in which Prisma Cloud Compute is deployed:

$ kubectl get pods -n twistlock
NAME                                                           READY   STATUS    RESTARTS   AGE
twistlock-console-855744b66b-xs9cm     1/1       Running          0           4d6h
twistlock-defender-ds-99zj7                       1/1       Running          0           58d
twistlock-defender-ds-drsh8                      1/1       Running          0           58d

Inspect the list of pods.

If a non-Prisma Cloud Compute (does not start with "twistlock") pod is running in the same namespace, this is a finding.'
  desc 'fix', 'Deploy the Prisma Cloud Compute Console and Defender containers within a distinct namespace.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56999r840477_chk'
  tag severity: 'medium'
  tag gid: 'V-253547'
  tag rid: 'SV-253547r840479_rule'
  tag stig_id: 'CNTR-PC-001380'
  tag gtitle: 'SRG-APP-000431-CTR-001065'
  tag fix_id: 'F-56950r840478_fix'
  tag 'documentable'
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
