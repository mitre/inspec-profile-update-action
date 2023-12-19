control 'SV-230761' do
  title 'The macOS system must be configured so that log folders must not contain access control lists (ACLs).'
  desc 'The audit service must be configured to create log folders with the correct permissions to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and users. If log folders are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', %q(To check if a log folder contains ACLs, run the following commands:

/usr/bin/sudo ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')

In the output from the above commands, ACLs will be listed under any folder that may contain them (e.g., "0: group:admin allow list,readattr,reaadextattr,readsecurity").

If any such line exists, this is a finding.)
  desc 'fix', 'For any log folder that contains ACLs, run the following command:

/usr/bin/sudo chmod -N [audit log folder]'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33706r607170_chk'
  tag severity: 'medium'
  tag gid: 'V-230761'
  tag rid: 'SV-230761r599842_rule'
  tag stig_id: 'APPL-11-000031'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-33679r607171_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
