control 'SV-240528' do
  title 'The SLES for vRealize must generate audit records when successful/unsuccessful logon attempts occur.'
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

OR

# /etc/dodscript.sh'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43761r671323_chk'
  tag severity: 'medium'
  tag gid: 'V-240528'
  tag rid: 'SV-240528r671325_rule'
  tag stig_id: 'VRAU-SL-001405'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag fix_id: 'F-43720r671324_fix'
  tag 'documentable'
  tag legacy: ['SV-100483', 'V-89833']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
