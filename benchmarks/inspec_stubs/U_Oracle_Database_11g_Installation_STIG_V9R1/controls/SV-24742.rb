control 'SV-24742' do
  title 'The IAM should review changes to DBA role assignments.'
  desc 'Unauthorized assignment of DBA privileges can lead to a compromise of DBMS integrity. Providing oversight to the authorization and assignment of privileges provides the separation of duty to support sufficient oversight.'
  desc 'check', 'Review policy and procedures documented or noted in the System Security Plan as well as evidence of implementation for monitoring changes to DBA role assignments and procedures for notifying the IAM of the changes for review.

If policy, procedures or implementation evidence do not exist, this is a Finding.'
  desc 'fix', 'Develop, document and implement procedures to monitor changes to DBA role assignments.

Develop, document and implement procedures to notify the IAM of changes to DBA role assignments.

Include in the procedures methods that provide evidence of monitoring and notification.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29353r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15127'
  tag rid: 'SV-24742r1_rule'
  tag stig_id: 'DG0118-ORACLE11'
  tag gtitle: 'IAM review of change in DBA assignments'
  tag fix_id: 'F-26378r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Manager'
end
