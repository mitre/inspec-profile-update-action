control 'SV-254100' do
  title 'Nutanix AOS role mapping must be configured to the lowest privilege level needed for user access.'
  desc 'Strong access controls are critical to securing the application server. Access control policies (e.g., identity-based policies, role-based policies, attribute-based policies) and access enforcement mechanisms (e.g., access control lists, access control matrices, cryptography) must be employed by the application server to control access between users (or processes acting on behalf of users) and objects (e.g., applications, files, records, processes, application domains) in the application server.

Without stringent logical access and authorization controls, an adversary may have the ability, with very little effort, to compromise the application server and associated supporting infrastructure.'
  desc 'check', 'Nutanix AOS supports user and group role mapping. Ensure all users or groups match that of the documented mapping policies defined by the ISSO.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to "role mapping".

For each user or group listed, ensure the role granted is according to access control policies. If not, this is a finding.'
  desc 'fix', 'Configure the user and group mappings to be compliant with the documented mapping policies defined by the ISSO.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to "role mapping".
4. Add users and groups to role mappings per policy.'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57585r846386_chk'
  tag severity: 'medium'
  tag gid: 'V-254100'
  tag rid: 'SV-254100r846388_rule'
  tag stig_id: 'NUTX-AP-000060'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-57536r846387_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
