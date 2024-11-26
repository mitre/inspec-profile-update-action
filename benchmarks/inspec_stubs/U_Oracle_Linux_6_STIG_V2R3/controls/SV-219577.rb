control 'SV-219577' do
  title 'The audit system must provide a warning when allocated audit record storage volume reaches a documented percentage of maximum audit record storage capacity.'
  desc 'Notifying administrators of an impending disk space problem may allow them to take corrective action prior to any disruption.'
  desc 'check', 'Inspect "/etc/audit/auditd.conf" and locate the following line to determine whether the system is configured to email the administrator when disk space is starting to run low: 

# grep space_left /etc/audit/auditd.conf 

space_left = [num_megabytes]

If the "num_megabytes" value does not correspond to a documented value for remaining audit partition capacity or if there is no locally documented value for remaining audit partition capacity, this is a finding.'
  desc 'fix', 'The "auditd" service can be configured to take an action when disk space starts to run low. Edit the file "/etc/audit/auditd.conf". Modify the following line, substituting [num_megabytes] appropriately: 

space_left = [num_megabytes]

The "num_megabytes" value should be set to a fraction of the total audit storage capacity available that will allow a system administrator to be notified with enough time to respond to the situation causing the capacity issues.  This value must also be documented locally.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21302r358271_chk'
  tag severity: 'medium'
  tag gid: 'V-219577'
  tag rid: 'SV-219577r603263_rule'
  tag stig_id: 'OL6-00-000311'
  tag gtitle: 'SRG-OS-000343'
  tag fix_id: 'F-21301r358272_fix'
  tag 'documentable'
  tag legacy: ['V-51051', 'SV-65257']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
