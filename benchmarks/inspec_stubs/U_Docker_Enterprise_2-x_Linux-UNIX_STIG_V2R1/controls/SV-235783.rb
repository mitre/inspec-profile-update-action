control 'SV-235783' do
  title 'Docker Enterprise sensitive host system directories must not be mounted on containers.'
  desc 'Sensitive host system directories such as below should not be allowed to be mounted as container volumes especially in read-write mode.

Linux:

/
/boot
/dev
/etc
/lib
/proc
/sys
/usr

Windows:

%windir% (C:\\Windows)
%windir%\\system32 (C:\\Windows\\system32)
%programdata%
%programData%\\docker
C:\\Program Files
C:\\Program Files (x86)
C:\\Users

If sensitive directories are mounted in read-write mode, it would be possible to make changes to files within those sensitive directories. The changes might bring down security implications or unwarranted changes that could put the Docker host in compromised state.

Docker defaults to a read-write volume but the user can also mount a directory read-only. By default, no sensitive host directories are mounted on containers.'
  desc 'check', %q(This check only applies to the use of Docker Engine - Enterprise.

Verify that no running containers have mounted sensitive host system directories. Refer to System Security Plan for list of sensitive folders.

via CLI:

Execute the following command as a trusted user on the host operating system:

docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Volumes={{ .Mounts }}' | grep -iv "ucp\|kubelet\|dtr"

Verify in the output that no containers are running with mounted RW access to sensitive host system directories. If there are containers mounted with RW access to sensitive host system directories, this is a finding.)
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise.

Do not mount host sensitive directories on containers especially in read-write mode.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39002r627474_chk'
  tag severity: 'medium'
  tag gid: 'V-235783'
  tag rid: 'SV-235783r627476_rule'
  tag stig_id: 'DKER-EE-001190'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-38965r627475_fix'
  tag 'documentable'
  tag legacy: ['SV-104737', 'V-95599']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
