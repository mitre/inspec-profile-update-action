control 'SV-53263' do
  title 'SQL Server must limit the use of resources by priority and not impede the host from servicing processes designated as a higher priority.'
  desc "Priority protection helps prevent a lower-priority process from delaying or interfering with the information system servicing any higher-priority process. This control does not apply to components in the information system for which there is only a single user/role. The application must limit the use of resources by priority.

SQL Server often runs queries for multiple users at the same time. If lower priority processes are utilizing a disproportionately high amount of database resources, this can severely impact higher priority processes.

Even if SQL Server's utilization is very small and there may seem to be no need to priority protection, often resources grow exponentially and must be implemented as part of an initial deployment."
  desc 'check', 'Review system documentation and determine if one type or more of SQL Server users has a business need for priority usage over other types of users. The need for prioritization most frequently occurs when SQL Server resources are shared between two or more applications or systems where the number of users on more than one system is small or non-existent. This needs to be the case, because SQL Server limits resource based on user accounts and not what process is running.

If SQL Server has users that are determined to run significantly high priority processes than other users and the SQL Server "Resource Governor" is not being implemented, this is a finding.'
  desc 'fix', 'SQL Server utilizes the "Resource Governor" to determine who is allowed high processing resources. There are several configurations regarding the "Resource Governor" that mostly comes down to users or groups of users having a "MAX_CPU_PERCENT", "MIN_CPU_PERCENT", "MIN_MEMORY_PERCENT", and/or "MAX_MEMORY_PERCENT" settings.

Users are assigned to Workgroups and the Workgroups are configured processing resources via the "Resource Governor".'
  impact 0.3
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47564r2_chk'
  tag severity: 'low'
  tag gid: 'V-40909'
  tag rid: 'SV-53263r2_rule'
  tag stig_id: 'SQL2-00-022300'
  tag gtitle: 'SRG-APP-000248-DB-000135'
  tag fix_id: 'F-46191r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002394']
  tag nist: ['SC-6']
end
