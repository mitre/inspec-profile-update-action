control 'SV-223481' do
  title 'ACF2 maintenance LOGONIDs must have corresponding GSO MAINT records.'
  desc 'Activity under unusual conditions can indicate hostile activity. For example, what is normal activity during business hours can indicate hostile activity if it occurs during off hours.

Depending on mission needs and conditions, account usage restrictions based on conditions and circumstances may be critical to limit access to resources and data to comply with operational or mission access control requirements. Thus, the operating system must be configured to enforce the specific conditions or circumstances under which organization-defined accounts can be used (e.g., by restricting usage to certain days of the week, time of day, or specific durations of time).'
  desc 'check', 'From the ACF Command screen enter:
SET LID
LIST IF(MAINT)

SET CONTROL(GSO)
LIST LIKE(MAINT-)

If every maintenance logonid has a corresponding GSO MAINT record, this is not a finding.'
  desc 'fix', 'Ensure that an associated GSO maintenance record exists for each special user logonid identifying the program(s) that it is permitted to access and the library where the program(s) resides.

Define associated GSO MAINT record for each special user logonid, identifying the program(s) that it is permitted to access and the library where the program(s) resides.

Every maintenance logonid has a corresponding GSO MAINT record.

Example:

SET C(GSO)
INSERT MAINT.DFSMSHSM LIBRARY(SYS1.LINKLIB) LID(HSMDFDSS) PGM(ADRDSSU) 

F ACF2,REFRESH(MAINT)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25154r695417_chk'
  tag severity: 'medium'
  tag gid: 'V-223481'
  tag rid: 'SV-223481r695419_rule'
  tag stig_id: 'ACF2-ES-000630'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25142r695418_fix'
  tag 'documentable'
  tag legacy: ['SV-106765', 'V-97661']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
