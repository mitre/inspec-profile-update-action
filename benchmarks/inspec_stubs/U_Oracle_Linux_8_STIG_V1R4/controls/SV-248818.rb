control 'SV-248818' do
  title 'OL 8 must take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.'
  desc 'check', 'Verify OL 8 takes action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity with the following commands: 
 
$ sudo grep -w space_left /etc/audit/auditd.conf 
 
space_left = 25% 
 
If the value of the "space_left" keyword is not set to "25%" or if the line is commented out, ask the SA to demonstrate how the system is providing real-time alerts to the SA and ISSO. 
 
If there is no evidence that real-time alerts are configured on the system, this is a finding.'
  desc 'fix', 'Configure OL 8 to initiate an action to notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity by adding/modifying the following line in the "/etc/audit/auditd.conf" file. 
 
space_left = 25%'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52252r780018_chk'
  tag severity: 'medium'
  tag gid: 'V-248818'
  tag rid: 'SV-248818r853843_rule'
  tag stig_id: 'OL08-00-030730'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-52206r780019_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
