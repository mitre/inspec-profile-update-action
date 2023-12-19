control 'SV-223485' do
  title 'ACF2 LOGONIDs assigned for started tasks must have the STC attribute specified in the associated LOGONID record.'
  desc 'Activity under unusual conditions can indicate hostile activity. For example, what is normal activity during business hours can indicate hostile activity if it occurs during off hours.

Depending on mission needs and conditions, account usage restrictions based on conditions and circumstances may be critical to limit access to resources and data to comply with operational or mission access control requirements. Thus, the operating system must be configured to enforce the specific conditions or circumstances under which organization-defined accounts can be used (e.g., by restricting usage to certain days of the week, time of day, or specific durations of time).'
  desc 'check', 'From the ACF command screen enter:
SET LID 
SET VERBOSE 
LIST IF(STC)

If all logonids identified as started tasks have the STC attribute specified, this is not a finding.'
  desc 'fix', 'All started tasks will be assigned an individual logonid. The logonid for a Started Task Control (STC) will be granted the minimum privileges necessary for the STC to function. In addition to the default LID field settings, all STC logonids will have the following field setting:

STC

Example:
SET LID
INSERT logonid STC'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25158r504564_chk'
  tag severity: 'medium'
  tag gid: 'V-223485'
  tag rid: 'SV-223485r533198_rule'
  tag stig_id: 'ACF2-ES-000670'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25146r504565_fix'
  tag 'documentable'
  tag legacy: ['V-97669', 'SV-106773']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
