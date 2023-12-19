control 'SV-80461' do
  title 'Trend Deep Security must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure an immediate warning is provided to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.

1. Analyze the system using the Administration > System Settings >> Alerts tab. Review the email address listed in the “Alert Event Forwarding (From The Manager).”

If this email address is not present or does not belong to a distribution for system administrator and ISSOs, this is a finding.

2. Analyze the system using the Administration >> System Settings >> System Events tab for “Manager Available Disk Space Too Low” Event ID 170. 

If the options for “Record” and “Forward” are not enabled for “Manager Available Disk Space Too Low”, this is a finding'
  desc 'fix', 'Configure the Trend Deep Security server to provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.

1. Configure Events and Alerts to notify the SA and ISSO using the Administration >> System Settings >> Alerts tab. Inset a distribution email address into the “Alert Event Forwarding (From The Manager).” The distribution email address must be configured within Exchange or other email server and must associate the SA and ISSO accounts reviewing and/or managing the system.

2. Configure the alert using the Administration >> System Settings >> System Events for “Manager Available Disk Space Too Low” Event ID 170. Select the options for “Record” and “Forward”.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66619r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65971'
  tag rid: 'SV-80461r1_rule'
  tag stig_id: 'TMDS-00-000270'
  tag gtitle: 'SRG-APP-000359'
  tag fix_id: 'F-72047r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
