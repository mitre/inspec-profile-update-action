control 'SV-223486' do
  title 'ACF2 emergency LOGONIDS with the REFRESH attribute must have the SUSPEND attribute specified.'
  desc 'Activity under unusual conditions can indicate hostile activity. For example, what is normal activity during business hours can indicate hostile activity if it occurs during off hours.

Depending on mission needs and conditions, account usage restrictions based on conditions and circumstances may be critical to limit access to resources and data to comply with operational or mission access control requirements. Thus, the operating system must be configured to enforce the specific conditions or circumstances under which organization-defined accounts can be used (e.g., by restricting usage to certain days of the week, time of day, or specific durations of time).'
  desc 'check', 'From the ACF Command screen enter:
SET LID
LIST IF(REFRESH)

If the logonid is an emergency logonid and the REFRESH attribute is not in SUSPEND status, this is a finding.'
  desc 'fix', 'The emergency logonids with the REFRESH attribute must be in SUSPEND status unless actually in use.

Example:
SET LID
CHANGE logonid SUSPEND'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25159r500590_chk'
  tag severity: 'medium'
  tag gid: 'V-223486'
  tag rid: 'SV-223486r533198_rule'
  tag stig_id: 'ACF2-ES-000680'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25147r500591_fix'
  tag 'documentable'
  tag legacy: ['V-97671', 'SV-106775']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
