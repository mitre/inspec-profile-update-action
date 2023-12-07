control 'SV-230412' do
  title 'Successful/unsuccessful uses of the su command in RHEL 8 must generate an audit record.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "su" command allows a user to run commands with a substitute user and group ID.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.

'
  desc 'check', 'Verify RHEL 8 generates audit records when successful/unsuccessful attempts to use the "su" command by performing the following command to check the file system rules in "/etc/audit/audit.rules": 

$ sudo grep -w /usr/bin/su /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to generate audit records when successful/unsuccessful attempts to use the "su" command occur by adding or updating the following rule in "/etc/audit/rules.d/audit.rules":

-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-33081r567982_chk'
  tag severity: 'medium'
  tag gid: 'V-230412'
  tag rid: 'SV-230412r627750_rule'
  tag stig_id: 'RHEL-08-030190'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-33056r567983_fix'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000064-GPOS-0003', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000466-GPOS-00210']
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
