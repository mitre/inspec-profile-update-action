control 'SV-240504' do
  title 'The SLES for vRealize must immediately notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately when storage volume reaches 75% utilization, they are unable to plan for audit record storage capacity expansion.'
  desc 'check', 'Check "/etc/audit/auditd.conf" for the" space_left_action" with the following command:

# cat /etc/audit/auditd.conf | grep space_left_action 

If the "space_left_action" parameter is missing, set to "ignore", set to "suspend", set to "single", set to "halt", or is blank, this is a finding.

Expected Result:
space_left_action = SYSLOG

NOTES: 
If the space_left_action is set to "exec" the system executes a designated script. If this script informs the SA of the event, this is not a finding.

If the space_left_action is set to "email" and the "action_mail_acct" parameter is not set to the email address of the system administrator, this is a finding. 

The "action_mail_acct parameter", if missing, defaults to "root". Note that if the email address of the system administrator is on a remote system "sendmail" must be available.'
  desc 'fix', 'Set the "space_left_action" parameter to the valid setting "SYSLOG",  by running the following command:

# sed -i "/^[^#]*space_left_action/ c\\admin_space_left_action = SYSLOG" /etc/audit/auditd.conf

Restart the audit service:

# service auditd restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43737r671251_chk'
  tag severity: 'medium'
  tag gid: 'V-240504'
  tag rid: 'SV-240504r671253_rule'
  tag stig_id: 'VRAU-SL-001065'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-43696r671252_fix'
  tag 'documentable'
  tag legacy: ['SV-100435', 'V-89785']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
