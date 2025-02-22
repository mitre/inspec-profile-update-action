control 'SV-208907' do
  title 'The audit system must be configured to audit successful file system mounts.'
  desc 'The unauthorized exportation of data to external media could result in an information leak where classified information, Privacy Act information, and intellectual property could be lost. An audit trail should be created each time a filesystem is mounted to help identify and guard against information loss.'
  desc 'check', 'To verify that auditing is configured for all media exportation events, run the following command:

$ sudo grep -w "mount" /etc/audit/audit.rules

-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k export
-a always,exit -F arch=b32 -S mount -F auid=0 -k export
-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export
-a always,exit -F arch=b64 -S mount -F auid=0 -k export

If the system is 64-bit and does not return rules for both "b32" and "b64" architectures, this is a finding.

If no line is returned, this is a finding.'
  desc 'fix', 'At a minimum, the audit system should collect media exportation events for all users and root. Add the following to "/etc/audit/audit.rules:

-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k export
-a always,exit -F arch=b32 -S mount -F auid=0 -k export

If the system is 64-bit, then also add the following:

-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export
-a always,exit -F arch=b64 -S mount -F auid=0 -k export'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9160r357701_chk'
  tag severity: 'low'
  tag gid: 'V-208907'
  tag rid: 'SV-208907r603263_rule'
  tag stig_id: 'OL6-00-000199'
  tag gtitle: 'SRG-OS-000064'
  tag fix_id: 'F-9160r357702_fix'
  tag 'documentable'
  tag legacy: ['V-51139', 'SV-65349']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
