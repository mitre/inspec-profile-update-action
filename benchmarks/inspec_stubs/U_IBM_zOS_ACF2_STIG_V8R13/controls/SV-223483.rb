control 'SV-223483' do
  title 'ACF2 LOGONIDs with the ACCOUNT, LEADER, or SECURITY attribute must be properly scoped.'
  desc 'Activity under unusual conditions can indicate hostile activity. For example, what is normal activity during business hours can indicate hostile activity if it occurs during off hours.

Depending on mission needs and conditions, account usage restrictions based on conditions and circumstances may be critical to limit access to resources and data to comply with operational or mission access control requirements. Thus, the operating system must be configured to enforce the specific conditions or circumstances under which organization-defined accounts can be used (e.g., by restricting usage to certain days of the week, time of day, or specific durations of time).'
  desc 'check', 'From the ACF command screen enter:
SET LID
LIST IF(ACCOUNT)
LIST IF(LEADER)
LIST IF(SECURITY)

Review all logonids for specific groups with the attributes ACCOUNT, LEADER, or SECURITY. 

If each has the SCPLIST attribute specified properly according to job function and areas of responsibility, this is not a finding.

NOTE: SCPLST attributes are not required for Domain Level Security Admin Logonids and BATCH Logonids that administer and modify the entire ACF2 environment to include GSO records, data set and resource rules, etc. or run audit reports.'
  desc 'fix', 'The following user attributes allow update of the ACF2 databases for administering users, data set access rules, and Infostorage records. When granted to a logonid, restrict the scope of the following attributes using an associated SCPLIST (scope list) record:

ACCOUNT
LEADER
SECURITY

NOTE: SCPLST attributes are not required for Domain Level Security Admin Logonids and BATCH Logonids that administer and modify the entire ACF2 environment to include GSO records, data set and resource rules, etc. or run audit reports.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25156r504558_chk'
  tag severity: 'medium'
  tag gid: 'V-223483'
  tag rid: 'SV-223483r533198_rule'
  tag stig_id: 'ACF2-ES-000650'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25144r504559_fix'
  tag 'documentable'
  tag legacy: ['SV-106769', 'V-97665']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
