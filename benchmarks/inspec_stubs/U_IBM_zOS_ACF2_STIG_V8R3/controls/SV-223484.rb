control 'SV-223484' do
  title 'ACF2 LOGONIDs associated with started tasks that have the MUSASS attribute and the requirement to submit jobs on behalf of its users must have the JOBFROM attribute as required.'
  desc 'Activity under unusual conditions can indicate hostile activity. For example, what is normal activity during business hours can indicate hostile activity if it occurs during off hours.

Depending on mission needs and conditions, account usage restrictions based on conditions and circumstances may be critical to limit access to resources and data to comply with operational or mission access control requirements. Thus, the operating system must be configured to enforce the specific conditions or circumstances under which organization-defined accounts can be used (e.g., by restricting usage to certain days of the week, time of day, or specific durations of time).'
  desc 'check', 'From the ACF command screen enter:
SET LID 
SET VERBOSE 
LIST IF(MUSASS)
LIST IF(STC)

If any started task logonid that has the MUSASS attribute and the requirement to submit jobs on behalf of its users does not have the JOBFROM attribute, this is a finding.'
  desc 'fix', 'Ensure that if MUSASS has the requirement to submit jobs on behalf of its users, the STC logonid has the JOBFROM attribute specified.

If the MUSASS has the requirement to submit jobs on behalf of its users, the STC logonid will also have the following attribute:

JOBFROM

Example:

SET LID
CHANGE logonid STC JOBFROM'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25157r504561_chk'
  tag severity: 'medium'
  tag gid: 'V-223484'
  tag rid: 'SV-223484r533198_rule'
  tag stig_id: 'ACF2-ES-000660'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25145r504562_fix'
  tag 'documentable'
  tag legacy: ['SV-106771', 'V-97667']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
