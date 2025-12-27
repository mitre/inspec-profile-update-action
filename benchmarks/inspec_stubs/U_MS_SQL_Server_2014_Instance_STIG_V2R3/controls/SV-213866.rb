control 'SV-213866' do
  title 'Execution of software modules (to include stored procedures, functions, and triggers) with elevated privileges must be restricted to necessary cases only.'
  desc 'In certain situations, to provide required functionality, a DBMS needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.

Privilege elevation must be utilized only where necessary and protected from misuse.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', 'Review the system documentation, SQL Server instance and database security configuration, source code for stored procedures, functions, and triggers, source code of external modules invoked by the DBMS, and source code of the application(s) using the database.

If elevation of DBMS privileges is utilized but not documented, this is a finding.

If elevation of DBMS privileges is documented, but not implemented as described in the documentation, this is a finding.

If the privilege-elevation logic can be invoked in ways other than intended, or in contexts other than intended, or by subjects/principals other than intended, this is a finding.'
  desc 'fix', 'Determine where, when, how, and by what principals/subjects elevated privilege is needed. 

Modify documentation as necessary to align it with the actual need for privilege elevation.

Modify the database and DBMS security configuration, stored procedures, functions, and triggers, external modules invoked by the DBMS, and the application(s) using the database, so that privilege elevation is used only as required.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15085r312949_chk'
  tag severity: 'medium'
  tag gid: 'V-213866'
  tag rid: 'SV-213866r855537_rule'
  tag stig_id: 'SQL4-00-032600'
  tag gtitle: 'SRG-APP-000342-DB-000302'
  tag fix_id: 'F-15083r312950_fix'
  tag 'documentable'
  tag legacy: ['SV-82377', 'V-67887']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
