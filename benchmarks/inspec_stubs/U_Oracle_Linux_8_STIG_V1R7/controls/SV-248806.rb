control 'SV-248806' do
  title 'OL 8 must allow only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict the roles and individuals that can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify that the "/etc/audit/rules.d/audit.rules" and "/etc/audit/auditd.conf" file have a mode of "0640" or less permissive by using the following commands: 
 
$ sudo ls -al /etc/audit/rules.d/audit.rules 
 
-rw-r----- 1 root root 1280 Feb 16 17:09 audit.rules 
 
$ sudo ls -al /etc/audit/auditd.conf 
 
-rw-r----- 1 root root 621 Sep 22 2014 auditd.conf 
 
If the "/etc/audit/rules.d/audit.rules" or "/etc/audit/auditd.conf" files have a mode more permissive than "0640", this is a finding.'
  desc 'fix', 'Configure the "/etc/audit/rules.d/audit.rules" and "/etc/audit/auditd.conf" files to have a mode of "0640" with the following commands: 
 
$ sudo chmod 0640 /etc/audit/rules.d/audit.rules 
$ sudo chmod 0640 /etc/audit/auditd.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52240r779982_chk'
  tag severity: 'medium'
  tag gid: 'V-248806'
  tag rid: 'SV-248806r779984_rule'
  tag stig_id: 'OL08-00-030610'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-52194r779983_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
