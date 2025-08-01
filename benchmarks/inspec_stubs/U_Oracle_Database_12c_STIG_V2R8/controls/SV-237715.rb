control 'SV-237715' do
  title 'Databases utilizing Discretionary Access Control (DAC) must enforce a policy that limits propagation of access rights.'
  desc 'Discretionary Access Control (DAC) is based on the premise that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment.

DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions. DAC models have the potential for the access controls to propagate without limit, resulting in unauthorized access to said objects.

When applications provide a discretionary access control mechanism, the application must be able to limit the propagation of those access rights.

The DBMS must ensure the recipient of permissions possesses only the access intended. The database must enforce the ability to limit rights propagation if that is the intent of the grantor. If the propagation of access rights is not limited, users with rights to objects they do not own can continue to grant rights to those objects to other users without limit.

This is default behavior for Oracle.'
  desc 'check', 'Verify the DBMS has the ability to grant permissions without the grantee receiving the right to grant those same permissions to another user.

Review organization policies regarding access propagation. If an access propagation policy limiting the propagation of rights does not exist, this is a finding.

Review DBMS configuration to verify access propagation policies are enforced by the DBMS as configured. If the DBMS does not enforce the access propagation policy, this is a finding.'
  desc 'fix', 'Create and document an access propagation policy that limits the propagation of rights.

Configure the DBMS to enforce the access propagation policy.

When a user is granted access to an object, they have access to the object.  When a user is granted access to an object with the GRANT option, then they can provide permissions to others.  Without the GRANT option, a user cannot grant access to an object.  No configuration is required.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40934r667175_chk'
  tag severity: 'medium'
  tag gid: 'V-237715'
  tag rid: 'SV-237715r879705_rule'
  tag stig_id: 'O121-C2-006600'
  tag gtitle: 'SRG-APP-000328-DB-000301'
  tag fix_id: 'F-40897r667176_fix'
  tag 'documentable'
  tag legacy: ['V-61617', 'SV-76107']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
