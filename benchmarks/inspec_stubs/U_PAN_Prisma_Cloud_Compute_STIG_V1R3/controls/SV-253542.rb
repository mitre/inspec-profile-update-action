control 'SV-253542' do
  title 'The node that runs Prisma Cloud Compute containers must have sufficient disk space to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'To ensure sufficient storage capacity in which to write the audit logs, Prisma Cloud compute must be able to allocate audit record storage capacity.'
  desc 'check', %q(When deploying Prisma Cloud Compute within a Kubernetes cluster, the Console's persistent value is by default 100GB. 

The logs are stored within this persistent volume. Within the Kubernetes cluster, issue the command "kubectl get pv".

If the twistlock/twistlock-console claim's capacity is not 100GB or greater, this is a finding.)
  desc 'fix', 'When deploying the Prisma Cloud Console, specify the size of the persistent volume with the "—persistent-volume-storage" parameter.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56994r840462_chk'
  tag severity: 'medium'
  tag gid: 'V-253542'
  tag rid: 'SV-253542r879730_rule'
  tag stig_id: 'CNTR-PC-001030'
  tag gtitle: 'SRG-APP-000357-CTR-000800'
  tag fix_id: 'F-56945r840463_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
