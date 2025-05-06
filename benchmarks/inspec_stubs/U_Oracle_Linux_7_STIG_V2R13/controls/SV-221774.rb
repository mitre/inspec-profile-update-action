control 'SV-221774' do
  title 'The Oracle Linux operating system must initiate an action to notify the System Administrator (SA) and Information System Security Officer (ISSO), at a minimum, when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.'
  desc 'check', 'Verify the operating system initiates an action to notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.

Check the system configuration to determine the partition the audit records are being written to with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Determine what the threshold is for the system to take action when 75 percent of the repository maximum audit record storage capacity is reached:

$ sudo grep -iw space_left /etc/audit/auditd.conf
space_left = 25%

If the value of the "space_left" keyword is not set to 25 percent of the total partition size, this is a finding.'
  desc 'fix', 'Configure the operating system to initiate an action to notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.

Set the value of the "space_left" keyword in "/etc/audit/auditd.conf" to 25 percent of the partition size.
space_left = 25%
Reload the auditd daemon to apply changes made to the "/etc/audit/auditd.conf" file.
$ sudo service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36293r744084_chk'
  tag severity: 'medium'
  tag gid: 'V-221774'
  tag rid: 'SV-221774r877389_rule'
  tag stig_id: 'OL07-00-030330'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-36257r744085_fix'
  tag 'documentable'
  tag legacy: ['V-99287', 'SV-108391']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
