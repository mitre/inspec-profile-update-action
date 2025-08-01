control 'SV-233156' do
  title 'The container platform must enforce organization-defined circumstances and/or usage conditions for organization-defined accounts.'
  desc 'Activity under unusual conditions can indicate hostile activity. For example, what is normal activity during business hours can indicate hostile activity if it occurs during off hours.

Depending on mission needs and conditions, account usage restrictions based on conditions and circumstances may be critical to limit access to resources and data to comply with operational or mission access control requirements. Thus, the application must be configured to enforce the specific conditions or circumstances under which application accounts can be used (e.g., by restricting usage to certain days of the week, time of day, or specific durations of time).'
  desc 'check', 'Determine if the container platform is configured to enforce organization-defined circumstances and/or usage conditions for organization-defined accounts. 

If the container platform does not enforce organization-defined circumstances and/or usage conditions for organization-defined accounts, this is a finding.'
  desc 'fix', 'Configure the container platform to enforce organization-defined circumstances and/or usage conditions for organization-defined accounts.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36092r601760_chk'
  tag severity: 'medium'
  tag gid: 'V-233156'
  tag rid: 'SV-233156r855341_rule'
  tag stig_id: 'SRG-APP-000318-CTR-000740'
  tag gtitle: 'SRG-APP-000318-CTR-000740'
  tag fix_id: 'F-36060r600956_fix'
  tag 'documentable'
  tag cci: ['CCI-002145']
  tag nist: ['AC-2 (11)']
end
