control 'SV-214931' do
  title 'The macOS system must be configured with access control lists (ACLs) for system log files to be set correctly.'
  desc 'System logs should only be readable by root or admin users. System logs frequently contain sensitive information that could be used by an attacker. Setting the correct ACLs mitigates this risk.'
  desc 'check', %q(These commands check for log files that exist on the system and print out the list of ACLs if there are any.

/usr/bin/sudo ls -ld@ $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
/usr/bin/sudo ls -ld@ $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null

ACLs will be listed under any file that may contain them (i.e., "0: group:admin allow list,readattr,reaadextattr,readsecurity").

If any system log file contains this information, this is a finding.)
  desc 'fix', 'For any log file that returns an ACL, run the following command:

/usr/bin/sudo chmod -N [log file]

[log file] is the full path to the log file in question.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16131r397365_chk'
  tag severity: 'medium'
  tag gid: 'V-214931'
  tag rid: 'SV-214931r609363_rule'
  tag stig_id: 'AOSX-13-002107'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-16129r397366_fix'
  tag 'documentable'
  tag legacy: ['SV-96457', 'V-81743']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
