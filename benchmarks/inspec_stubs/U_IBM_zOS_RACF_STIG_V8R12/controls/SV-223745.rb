control 'SV-223745' do
  title 'IBM z/OS RJE workstations and NJE nodes must be defined to the FACILITY resource class.'
  desc 'Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Refer to SYS1.PARMLIB (JES2PARM)
For each node entry

If all JES2 defined NJE nodes and RJE workstations have a profile defined in the FACILITY resource class, this is not a finding.

Notes: Nodename is the NAME parameter value specified on the NODE statement. Review the JES2 parameters for NJE node definitions by searching for NODE( in the report.
Workstation is RMTnnnn, where nnnn is the number on the RMT statement. Review the JES2 parameters for RJE workstation definitions by searching for RMT( in the report.
NJE.* and RJE.* profiles will force userid and password protection of all NJE and RJE connections respectively. This method is acceptable in lieu of using discrete profiles.'
  desc 'fix', 'Configure associated PROFILEs TO exist for all RJE/NJE sources and review the authorizations for these remote facilities.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25418r514923_chk'
  tag severity: 'medium'
  tag gid: 'V-223745'
  tag rid: 'SV-223745r604139_rule'
  tag stig_id: 'RACF-JS-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25406r514924_fix'
  tag 'documentable'
  tag legacy: ['V-98197', 'SV-107301']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
