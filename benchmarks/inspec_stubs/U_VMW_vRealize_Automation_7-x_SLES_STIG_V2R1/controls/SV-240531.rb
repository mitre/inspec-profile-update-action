control 'SV-240531' do
  title 'The SLES for vRealize must generate audit records showing starting and ending time for user access to the system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'The message types that are always recorded to /var/log/audit/audit.log include "LOGIN", "USER_LOGIN", "USER_START", "USER_END" among others and do not need to be added to audit.rules.

The log files /var/log/faillog, /var/log/lastlog, and /var/log/tallylog must be protected from tampering of the logon records:

# egrep "faillog|lastlog|tallylog" /etc/audit/audit.rules

If /var/log/faillog, /var/log/lastlog, and /var/log/tallylog entries do not exist, this is a finding.'
  desc 'fix', 'Ensure the auditing of logons by modifying /etc/audit/audit.rules to contain:

-w /var/log/faillog -p wa
-w /var/log/lastlog -p wa
-w /var/log/tallylog -p wa

OR...

# /etc/dodscript.sh'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43764r671332_chk'
  tag severity: 'medium'
  tag gid: 'V-240531'
  tag rid: 'SV-240531r671334_rule'
  tag stig_id: 'VRAU-SL-001420'
  tag gtitle: 'SRG-OS-000472-GPOS-00217'
  tag fix_id: 'F-43723r671333_fix'
  tag 'documentable'
  tag legacy: ['SV-100489', 'V-89839']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
