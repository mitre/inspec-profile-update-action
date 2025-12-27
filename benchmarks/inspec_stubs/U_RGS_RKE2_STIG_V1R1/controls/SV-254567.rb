control 'SV-254567' do
  title 'Rancher RKE2 must store only cryptographic representations of passwords.'
  desc 'Secrets, such as passwords, keys, tokens, and certificates should not be stored as environment variables. These environment variables are accessible inside RKE2 by the "Get Pod" API call, and by any system, such as CI/CD pipeline, which has access to the definition file of the container. Secrets must be mounted from files or stored within password vaults.'
  desc 'check', %q(On the RKE2 Control Plane, run the following command:

kubectl get all -o jsonpath='{range .items[?(@..secretKeyRef)]} {.kind} {.metadata.name} {"\n"}{end}' -A

If any of the values returned reference environment variables, this is a finding.)
  desc 'fix', 'Any secrets stored as environment variables must be moved to the secret files with the proper protections and enforcements or placed within a password vault.'
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58051r859269_chk'
  tag severity: 'medium'
  tag gid: 'V-254567'
  tag rid: 'SV-254567r859271_rule'
  tag stig_id: 'CNTR-R2-000800'
  tag gtitle: 'SRG-APP-000171-CTR-000435'
  tag fix_id: 'F-58000r859270_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
