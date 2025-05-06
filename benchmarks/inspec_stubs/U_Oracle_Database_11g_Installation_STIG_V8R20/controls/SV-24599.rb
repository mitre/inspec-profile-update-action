control 'SV-24599' do
  title 'Configuration management procedures should be defined and implemented for database software modifications.'
  desc 'Uncontrolled, untested, or unmanaged changes result in an unreliable security posture. All changes to software libraries related to the database and its use need to be reviewed, considered, and the responsibility for CM assigned. CM responsibilities may appear to cross boundaries. It is important, however, for the boundaries of CM responsibility to be clearly defined and assigned to ensure no libraries or configurations are left unaddressed. Related database application libraries may include third-party DBMS management tools, DBMS stored procedures, or other end-user applications.'
  desc 'check', 'Interview the IAO and review documentation to determine if a configuration management (CM) process is implemented for the DBMS system that includes requirements for:
  (1) Formally documented CM roles, responsibilities, and procedures to include the management of IA information and documentation;
  (2) A configuration control board that implements procedures to ensure a security review and approval of all proposed DoD information system changes, to include interconnections to other DoD information systems;
  (3) A testing process to verify proposed configuration changes prior to implementation in the operational environment; and
  (4) A verification process to provide additional assurance that the CM process is working effectively and that changes outside the CM process are technically or procedurally not permitted.

If documented evidence for procedures or processes outlined above are not present or are incomplete, this is a Finding.'
  desc 'fix', 'Develop, document and implement configuration management procedures or processes.

Ensure the 4 major requirements listed in the check are documented at a minimum.

Assign responsibilities for oversight and approval for any and all changes made to DBMS software and configuration.'
  impact 0.3
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-1257r1_chk'
  tag severity: 'low'
  tag gid: 'V-3726'
  tag rid: 'SV-24599r1_rule'
  tag stig_id: 'DG0011-ORACLE11'
  tag gtitle: 'DBMS Configuration Management'
  tag fix_id: 'F-3780r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
