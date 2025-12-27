control 'SV-24979' do
  title 'DBA roles assignments should be assigned and authorized by the IAO.'
  desc 'The DBA role and associated privileges provide complete control over the DBMS operation and integrity. DBA role assignment without authorization could lead to the assignment of these privileges to untrusted and untrustworthy persons and complete compromise of DBMS integrity.'
  desc 'check', 'Review the documented procedures for approval and granting of DBA privileges.

Review implementation evidence for the procedures.

If procedures do not exist or evidence that they are followed does not exist, this is a Finding.'
  desc 'fix', 'Develop, document and implement procedures to ensure all DBA role assignments are authorized and assigned by the IAO.

Include methods that provide evidence of approval in the procedures.'
  impact 0.3
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-3818r1_chk'
  tag severity: 'low'
  tag gid: 'V-15149'
  tag rid: 'SV-24979r1_rule'
  tag stig_id: 'DG0153-ORACLE11'
  tag gtitle: 'DBMS DBA roles assignment approval'
  tag fix_id: 'F-20278r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
