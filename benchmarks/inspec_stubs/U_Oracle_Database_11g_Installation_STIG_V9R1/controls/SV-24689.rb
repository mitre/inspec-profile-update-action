control 'SV-24689' do
  title 'The DBMS IA policies and procedures should be reviewed annually or more frequently.'
  desc 'A regular review of current database security policies and procedures is necessary to maintain the desired security posture of the DBMS. Policies and procedures should be measured against current DoD policy, STIG guidance, vendor-specific guidance and recommendations, and site-specific or other security policies.'
  desc 'check', 'Review documented policy and procedures included or noted in the System Security Plan as well as evidence of implementation for annual reviews of DBMS IA policy and procedures.

If policy and procedures do not exist, are incomplete, or are not implemented and followed annually or more frequently, this is a Finding.'
  desc 'fix', 'Develop, document and implement procedures to review DBMS IA policies and procedures.'
  impact 0.3
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29227r1_chk'
  tag severity: 'low'
  tag gid: 'V-15138'
  tag rid: 'SV-24689r1_rule'
  tag stig_id: 'DG0096-ORACLE11'
  tag gtitle: 'DBMS IA policy and procedure review'
  tag fix_id: 'F-26248r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
