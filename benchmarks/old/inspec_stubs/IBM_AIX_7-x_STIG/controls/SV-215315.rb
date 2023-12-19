control 'SV-215315' do
  title 'The AIX audit configuration files must be owned by root.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', %q(Check that all the audit configuration files under /etc/security/audit/* have correct ownership. 

# ls -l /etc/security/audit/*
-rw-r-----    1 root     audit            37 Oct 10 2016  /etc/security/audit/bincmds
-rw-r-----    1 root     audit          2838 Sep 05 16:33 /etc/security/audit/config
-rw-r-----    1 root     audit         26793 Oct 10 2016  /etc/security/audit/events
-rw-r-----    1 root     audit           340 Oct 10 2016  /etc/security/audit/objects
-rw-r-----    1 root     audit            54 Oct 10 2016  /etc/security/audit/streamcmds

If any file's ownership is not "root", this is a finding.)
  desc 'fix', 'Set the owner audit configuration files to "root".
# chown root /etc/security/audit/*'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16513r294396_chk'
  tag severity: 'medium'
  tag gid: 'V-215315'
  tag rid: 'SV-215315r508663_rule'
  tag stig_id: 'AIX7-00-002200'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-16511r294397_fix'
  tag 'documentable'
  tag legacy: ['SV-101369', 'V-91271']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
