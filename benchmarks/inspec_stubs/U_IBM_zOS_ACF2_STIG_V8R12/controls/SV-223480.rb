control 'SV-223480' do
  title 'ACF2 REFRESH attribute must be restricted to security administrators only.'
  desc 'Activity under unusual conditions can indicate hostile activity. For example, what is normal activity during business hours can indicate hostile activity if it occurs during off hours.

Depending on mission needs and conditions, account usage restrictions based on conditions and circumstances may be critical to limit access to resources and data to comply with operational or mission access control requirements. Thus, the operating system must be configured to enforce the specific conditions or circumstances under which organization-defined accounts can be used (e.g., by restricting usage to certain days of the week, time of day, or specific durations of time).'
  desc 'check', 'From the ACF Command screen enter:
SET LID
LIST IF(REFRESH)

If logonids exist with the REFRESH attribute not assigned to a site security administrator, this is a finding.'
  desc 'fix', 'Define any logonid with the REFRESH attribute to be assigned to a site security administrator only.

Example:
SET LID
CHANGE logonid REFRESH'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25153r500572_chk'
  tag severity: 'medium'
  tag gid: 'V-223480'
  tag rid: 'SV-223480r533198_rule'
  tag stig_id: 'ACF2-ES-000620'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25141r500573_fix'
  tag 'documentable'
  tag legacy: ['SV-106763', 'V-97659']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
