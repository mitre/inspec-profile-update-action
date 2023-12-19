control 'SV-223474' do
  title 'IBM z/OS batch jobs with restricted ACF2 LOGONIDs must have the PGM(xxxxxxxx) and SUBAUTH attributes or the SOURCE(xxxxxxxx) attribute assigned to the corresponding LOGONIDs.'
  desc 'Activity under unusual conditions can indicate hostile activity. For example, what is normal activity during business hours can indicate hostile activity if it occurs during off hours.

Depending on mission needs and conditions, account usage restrictions based on conditions and circumstances may be critical to limit access to resources and data to comply with operational or mission access control requirements. Thus, the operating system must be configured to enforce the specific conditions or circumstances under which organization-defined accounts can be used (e.g., by restricting usage to certain days of the week, time of day, or specific durations of time).'
  desc 'check', 'From the ACF command screen enter:
SET LID 
SET VERBOSE 
LIST IF(RESTRICT)

If the logonids that are associated with batch jobs have the RESTRICT attribute, then the logonids must also have the PGM(xxxxxxxx) and SUBAUTH attributes, or the SOURCE(xxxxxxxx) attribute specified.

If all restricted logonids have the PGM(xxxxxxxx) and SUBAUTH attributes, and/or the SOURCE(xxxxxxxx) attribute, this is not a finding.

If the PGM(xxxxxxxx) and SUBAUTH attributes or the SOURCE(xxxxxxxx) attribute is not specified for any restricted logonids, this is a finding.'
  desc 'fix', "All batch jobs scheduled via an automation process will use the //*LOGONID xxxxxxxx card in the JCL stream to identify the userid. Use restricted logonids with the following parameter coded:

RESTRICT

One or both of the following will also be specified:

PGM(xxxxxxxx) and SUBAUTH
SOURCE(xxxxxxxx)

The use of default IDs prevents the identification of tasks with individual users as mandated by policy, and prevents adequate accountability. Default IDs for batch processing will not be used.

The use of USER= can also be used in the jobcard to identify the userid to be used for a job's processing."
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25147r504537_chk'
  tag severity: 'medium'
  tag gid: 'V-223474'
  tag rid: 'SV-223474r533198_rule'
  tag stig_id: 'ACF2-ES-000560'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25135r504538_fix'
  tag 'documentable'
  tag legacy: ['V-97647', 'SV-106751']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
