control 'SV-253524' do
  title "Users requiring access to Prisma Cloud Compute's Credential Store must be assigned and accessed by the appropriate role holders."
  desc 'The container platform keystore is used to store credentials that are used to build a trust between the container platform and an external source. This trust relationship is authorized by the organization. If a malicious user were to have access to the container platform keystore, two negative scenarios could develop:

1. Keys not approved could be introduced. 
2. Approved keys could be deleted, leading to the introduction of container images from sources the organization never approved. 

To thwart this threat, it is important to protect the container platform keystore and give access to only individuals and roles approved by the organization.

'
  desc 'check', "Navigate to Prisma Cloud Compute Console's >> Manage >> Authentication >> Users tab. 

Inspect the users' role assignments:
- Review role assigned to users. If role and/or the Collection assignment is incorrect, this is a finding.
- If a user is not assigned a role, this is a finding. 
- Review users assigned the administrator role. If a user has the administrator role and does not require access, this is a finding.

Navigate to Prisma Cloud Compute Console's >> Manage >> Authentication >> Groups tab.

(Only the Administrator, Operator Prisma Cloud Compute roles have the ability to create/modify policy that could affect runtime behaviors.)

Inspect the groups' role assignments:
- If any users or groups are assigned the Auditor or higher role and do not require access to audit information, this is a finding.
- If a group is not assigned a role, this is a finding. 
- If role and/or Collection assignment is incorrect, this is a finding.
- Review groups assigned the Administrator or Operator role. If a group has the Administrator or Operator role and does not require access to Prisma Cloud Compute's Credential Store, this is a finding."
  desc 'fix', "Navigate to Prisma Cloud Compute Console's >> Manage >> Authentication >> Users tab. 

- Set the users' role assignments to the ones who have the authority to review the audit data.
- Assign roles to all users and groups. 
- Assign administrator and operator roles only to the users requiring the rights to modify the Prisma Cloud Compute's Credential Store. 
- Remove the Administrator or Operator role for users who do not require access. 

Navigate to Prisma Cloud Compute Console's >> Manage >> Authentication >> Groups tab.

- Set the groups' role assignments to the ones who have the authority to review audit data.
- Assign roles to all users and groups. 
- Set the groups' Administrator and Operator role assignments to only to the groups requiring the rights to modify the Prisma Cloud Compute's Credential Store.

Adjust user, group, and Collection assignments to align with organizational policies."
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56976r840408_chk'
  tag severity: 'medium'
  tag gid: 'V-253524'
  tag rid: 'SV-253524r840410_rule'
  tag stig_id: 'CNTR-PC-000120'
  tag gtitle: 'SRG-APP-000033-CTR-000100'
  tag fix_id: 'F-56927r840409_fix'
  tag satisfies: ['SRG-APP-000033-CTR-000100', 'SRG-APP-000118-CTR-000240', 'SRG-APP-000121-CTR-000255', 'SRG-APP-000133-CTR-000300', 'SRG-APP-000211-CTR-000530', 'SRG-APP-000233-CTR-000585', 'SRG-APP-000340-CTR-000770', 'SRG-APP-000380-CTR-000900']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000213', 'CCI-001082', 'CCI-001084', 'CCI-001493', 'CCI-001499', 'CCI-001813', 'CCI-002235']
  tag nist: ['AU-9 a', 'AC-3', 'SC-2', 'SC-3', 'AU-9 a', 'CM-5 (6)', 'CM-5 (1) (a)', 'AC-6 (10)']
end
