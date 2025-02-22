control 'SV-206600' do
  title 'The DBMS must require users to re-authenticate when organization-defined circumstances or situations require re-authentication.'
  desc 'The DoD standard for authentication of an interactive user is the presentation of a Common Access Card (CAC) or other physical token bearing a valid, current, DoD-issued Public Key Infrastructure (PKI) certificate, coupled with a Personal Identification Number (PIN) to be entered by the user at the beginning of each session and whenever re-authentication is required.

Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When applications provide the capability to change security roles or escalate the functional capability of the application, it is critical the user re-authenticate.

In addition to the re-authentication requirements associated with session locks, organizations may require re-authentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances:

(i) When authenticators change; 
(ii) When roles change; 
(iii) When security categories of information systems change; 
(iv) When the execution of privileged functions occurs; 
(v) After a fixed period of time; or
(vi) Periodically.

Within the DoD, the minimum circumstances requiring re-authentication are privilege escalation and role changes.'
  desc 'check', 'Review the system documentation and the configuration of the DBMS and related applications and tools.

If there are any circumstances under which a user is not required to re-authenticate when changing role or escalating privileges, this is a finding.

If the information owner has identified additional cases where re-authentication is needed, but there are circumstances where the system does not ask the user to re-authenticate when those cases occur, this is a finding.'
  desc 'fix', 'Modify and/or configure the DBMS and related applications and tools so that users are always required to re-authenticate when changing role or escalating privileges.

Modify and/or configure the DBMS and related applications and tools so that users are always required to re-authenticate when the specified cases needing reauthorization occur.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6860r291468_chk'
  tag severity: 'medium'
  tag gid: 'V-206600'
  tag rid: 'SV-206600r617447_rule'
  tag stig_id: 'SRG-APP-000389-DB-000372'
  tag gtitle: 'SRG-APP-000389'
  tag fix_id: 'F-6860r291469_fix'
  tag 'documentable'
  tag legacy: ['V-58147', 'SV-72577']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
