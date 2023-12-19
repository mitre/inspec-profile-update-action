control 'SV-223489' do
  title 'ACF2 MAINT GSO record value if specified must be restricted to production storage management user.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the operating system level.

Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).'
  desc 'check', 'From the ACF Command screen enter:
SET CONTROL(GSO)
LIST LIKE(MAINT-)

If the GSO MAINT record values conform to the following requirements, this is not a finding.

Specifies the logonid, program, and library combinations used for system maintenance functions. 
NOTE: For logonids that match environments described in records, no SMF logging records will be created. 
NOTE: Entries will be restricted to production storage management user accounts and programs. 

If there is any deviation from the above requirements in the GSO MAINT record values, this is a finding.'
  desc 'fix', 'Configure the MAINT GSO value to be specified as restricted to production storage management user accounts and programs.

Specifies the logonid, program, and library combinations used for system maintenance functions.
NOTE: For logonids that match environments described in records, no SMF logging records will be created.
NOTE: Entries will be restricted to production storage management user accounts and programs.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25162r504573_chk'
  tag severity: 'medium'
  tag gid: 'V-223489'
  tag rid: 'SV-223489r533198_rule'
  tag stig_id: 'ACF2-ES-000710'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-25150r504574_fix'
  tag 'documentable'
  tag legacy: ['V-97677', 'SV-106781']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
