control 'SV-215317' do
  title 'The AIX audit configuration files must be set to 640 or less permissive.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Check that all the audit configuration files under /etc/security/audit/* have correct permissions. 

# ls -l /etc/security/audit/*
-rw-r-----    1 root     audit            37 Oct 10 2016  /etc/security/audit/bincmds
-rw-r-----    1 root     audit          2838 Sep 05 16:33 /etc/security/audit/config
-rw-r-----    1 root     audit         26793 Oct 10 2016  /etc/security/audit/events
-rw-r-----    1 root     audit           340 Oct 10 2016  /etc/security/audit/objects
-rw-r-----    1 root     audit            54 Oct 10 2016  /etc/security/audit/streamcmds

If any file has a mode more permissive than "640",  this is a finding.'
  desc 'fix', 'Change the permission of the audit configuration files to "640".
# chmod 640 /etc/security/audit/*'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16515r294402_chk'
  tag severity: 'medium'
  tag gid: 'V-215317'
  tag rid: 'SV-215317r508663_rule'
  tag stig_id: 'AIX7-00-002202'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-16513r294403_fix'
  tag 'documentable'
  tag legacy: ['SV-101373', 'V-91275']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
