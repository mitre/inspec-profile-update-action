control 'SV-257159' do
  title 'The macOS system must be configured so that log folders do not contain access control lists (ACLs).'
  desc 'The audit service must be configured to create log folders with the correct permissions to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and users. If log folders are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', %q(Verify the macOS system is configured without ACLs applied to log folders with the following command:

/usr/bin/sudo /bin/ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')

In the output from the above command, ACLs will be listed under any folder that may contain them (e.g., "0: group:admin allow list,readattr,readextattr,readsecurity").

If any ACLs exists, this is a finding.)
  desc 'fix', 'Configure the macOS system so that log folders do not contain ACLs with the following command:

/usr/bin/sudo /bin/chmod -N [audit log folder]'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60844r905108_chk'
  tag severity: 'medium'
  tag gid: 'V-257159'
  tag rid: 'SV-257159r905110_rule'
  tag stig_id: 'APPL-13-000031'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-60785r905109_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
