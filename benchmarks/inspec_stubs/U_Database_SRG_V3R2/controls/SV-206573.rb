control 'SV-206573' do
  title 'The DBMS must prevent unauthorized and unintended information transfer via shared system resources.'
  desc 'The purpose of this control is to prevent information, including encrypted representations of information, produced by the actions of a prior user/role (or the actions of a process acting on behalf of a prior user/role) from being available to any current user/role (or current process) that obtains access to a shared system resource (e.g., registers, main memory, secondary storage) after the resource has been released back to the information system. Control of information in shared resources is also referred to as object reuse.'
  desc 'check', 'Review the DBMS architecture to find out if and how it protects the private resources of one process or user (such as working memory, temporary tables, uncommitted data) from unauthorized access by another user or process.

If it does not effectively do so, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of effectively protecting the private resources of one process or user from unauthorized access by another user or process.

Configure the DBMS to effectively protect the private resources of one process or user from unauthorized access by another user or process.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6833r291387_chk'
  tag severity: 'medium'
  tag gid: 'V-206573'
  tag rid: 'SV-206573r617447_rule'
  tag stig_id: 'SRG-APP-000243-DB-000373'
  tag gtitle: 'SRG-APP-000243'
  tag fix_id: 'F-6833r291388_fix'
  tag 'documentable'
  tag legacy: ['SV-72579', 'V-58149']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
