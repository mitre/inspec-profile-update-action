control 'SV-76927' do
  title 'ColdFusion must protect newly created objects.'
  desc 'During operation, ColdFusion may create objects such as files to store parameters or log data, or pipes to share data between objects.  When the objects are created, it is important that the newly created object has the correct permissions.  This can be performed by assigning the proper umask value to the running process.  For the ColdFusion service, the umask must be set to 007 or more restrictive.'
  desc 'check', 'For ColdFusion running on Windows, this finding is not applicable.

ColdFusion running on Linux:
1. Locate the file coldfusion_11 by running the command: find / -name coldfusion_11
2. Change to the directory where the file is located.
3. Edit the coldfusion_11 file.
4. Locate the umask setting.  It should be located near the top of the file, but below the #description comment.

If the umask is not set to 007 or more restrictive, this is a finding.'
  desc 'fix', 'For ColdFusion running on Windows, this finding is not applicable.

1. Locate the file coldfusion_11 by running the command: find / -name coldfusion_11
2. Change to the directory where the file is located.
3. Edit the coldfusion_11 file.
4. Add the umask setting near the top of the file, but below the #description comment.  A sample umask setting looks like: umask 007'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63241r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62437'
  tag rid: 'SV-76927r1_rule'
  tag stig_id: 'CF11-03-000113'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-68357r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
