control 'SV-215252' do
  title 'AIX must provide the function for assigned ISSOs or designated SAs to change the auditing to be performed on all operating system components, based on all selectable event criteria in near real time.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to effectively respond, and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting.'
  desc 'check', 'Verify that an audit admin role has been configured to include the authorizations for auditing, namely "aix.security.audit,aix.security.user.audit,aix.security.role.audit": 

# lsrole ALL |grep "aix.security.audit" |grep "aix.security.user.audit" |grep "aix.security.role.audit"
auditadm authorizations=aix.security.audit,aix.security.user.audit,aix.security.role.audit rolelist= groups= visibility=1 screens=* dfltmsg=Audit Administrator msgcat=role_desc.cat msgnum=15 msgset=1 auth_mode=INVOKER id=16

If the above command has no output, this is a finding.'
  desc 'fix', 'Create a role "auditadm" that is assigned with security related authorization with the following commend:
# mkrole authorizations="aix.security.audit,aix.security.user.audit,aix.security.role.audit" auditadm'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16450r294207_chk'
  tag severity: 'medium'
  tag gid: 'V-215252'
  tag rid: 'SV-215252r508663_rule'
  tag stig_id: 'AIX7-00-002032'
  tag gtitle: 'SRG-OS-000337-GPOS-00129'
  tag fix_id: 'F-16448r294208_fix'
  tag 'documentable'
  tag legacy: ['V-91515', 'SV-101613']
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
