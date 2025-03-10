control 'SV-223960' do
  title 'CA-TSS must use propagation control to eliminate ACID inheritance.'
  desc 'In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by the organizations.

Some programs and processes are required to operate at a higher privilege level and therefore should be excluded from the organization-defined software list after review.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY FACILITY(ALL)

enter
TSS MODIFY FACILITY(<FACILITY>)

If no Facility is defined with both the "MULTIUSER" and "ASUBM" attributes further analysis is not needed.

For each Facility with "MULTIUSER" and "ASUBM" attribute, review the @ACIDS report to determine which ACID(s) has (have) the following:

-A Master Facility of the Facility with "MULTIUSER" and "ASUBM" attribute, and,
-The Facility of "BATCH"

If each ACID that has the Master Facility of the Facility with "MULTIUSER" and "ASUBM" attribute and the Facility of "BATCH" is defined to the "PROPCNTL" resource class, this is not a finding.'
  desc 'fix', 'Ensure an associated ACID exists for all batch jobs and propagation control is being used. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes as required.

The following Example shows the CONTROL-M STC ACID being owned to the PROPCNTL resource class:
TSS ADD(deptacid) PROPCNTL(control-m-acid)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25633r516279_chk'
  tag severity: 'medium'
  tag gid: 'V-223960'
  tag rid: 'SV-223960r877801_rule'
  tag stig_id: 'TSS0-ES-000870'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag fix_id: 'F-25621r516280_fix'
  tag 'documentable'
  tag legacy: ['SV-107731', 'V-98627']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
