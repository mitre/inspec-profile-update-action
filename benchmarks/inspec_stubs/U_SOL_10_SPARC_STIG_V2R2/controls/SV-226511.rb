control 'SV-226511' do
  title 'The /etc/nsswitch.conf file must be group-owned by root, bin, or sys.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'check', 'Check the group ownership of the nsswitch.conf file.

Procedure:
# ls -lL /etc/nsswitch.conf

If the file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/nsswitch.conf file to root, bin, or sys.

Procedure:
# chgrp root /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28672r482921_chk'
  tag severity: 'medium'
  tag gid: 'V-226511'
  tag rid: 'SV-226511r603265_rule'
  tag stig_id: 'GEN001372'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28660r482922_fix'
  tag 'documentable'
  tag legacy: ['V-22328', 'SV-39897']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
