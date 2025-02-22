control 'SV-246831' do
  title 'The HYCU server must generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'HYCU Web UI user access accounts cannot be edited, only removed and readded from/to user groups in the Web UI Self-Service menu.

After adding a user to a group, log on to the HYCU Web UI, navigate into Events context, and search for message of category "USER_GROUP" and text "Successfully added user to group". Events cannot be modified. 

Log on to the VM console and run the following command:
chkconfig auditd 

If the Audit Service is not in a running state, this is a finding. 

Verify the operating system generates audit records when successful/unsuccessful attempts to access privileges occur. 

If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to access privileges occur.

Log on to the HYCU VM console and run the following command:
chkconfig auditd on

Log on to the HYCU VM console and load the STIG audit rules by using the following commands:

1. sudo cp /usr/share/audit/sample-rules/10-base-config.rules /usr/share/audit/sample-rules/30-stig.rules /usr/share/audit/sample-rules/31-privileged.rules /usr/share/audit/sample-rules/99-finalize.rules /etc/audit/rules.d/

2. sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50263r768155_chk'
  tag severity: 'medium'
  tag gid: 'V-246831'
  tag rid: 'SV-246831r768157_rule'
  tag stig_id: 'HYCU-AU-000002'
  tag gtitle: 'SRG-APP-000091-NDM-000223'
  tag fix_id: 'F-50217r768156_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
