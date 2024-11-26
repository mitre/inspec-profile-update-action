control 'SV-218456' do
  title 'Access to the at utility must be controlled via the at.allow and/or at.deny file(s).'
  desc 'The "at" facility selectively allows users to execute jobs at deferred times.  It is usually used for one-time jobs. The at.allow file selectively allows access to the "at" facility.  If there is no at.allow file, there is no ready documentation of who is allowed to submit "at" jobs.'
  desc 'check', 'If the "at" package is not installed, this is not applicable.

Check for the existence of at.allow and at.deny files.
# ls -lL /etc/at.allow
# ls -lL /etc/at.deny
If neither file exists, this is a finding.'
  desc 'fix', 'Create at.allow and/or at.deny files containing appropriate lists of users to be allowed or denied access to the "at" daemon.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19931r562525_chk'
  tag severity: 'medium'
  tag gid: 'V-218456'
  tag rid: 'SV-218456r603259_rule'
  tag stig_id: 'GEN003280'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19929r562526_fix'
  tag 'documentable'
  tag legacy: ['V-984', 'SV-64369']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
