control 'SV-252631' do
  title 'The IBM Aspera High-Speed Transfer Server must configure the SELinux context type to allow the "aspshell".'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.'
  desc 'check', 'Verify the IBM Aspera HSTS configures the SELinux context type for "aspshell" with the following commands:

$ sudo ls -l /bin/aspshell

lrwxrwxrwx. 1 root root 24 Sep 1 17:38 /bin/aspshell -> /opt/aspera/bin/aspshell

If /bin/aspshell is not simlinked to /opt/aspera/bin/aspshell, this is a finding.

$ sudo ls -Z /opt/aspera/bin/aspshell

-rwxr-xr-x. root root system_u:object_r:shell_exec_t:S0 /bin/aspshell

If the context type of "/opt/aspera/bin/aspshell" is not "shell_exec_t", this is a finding.'
  desc 'fix', 'Configure the IBM Aspera HSTS SELinux context type for "aspshell" with the following commands:

$ sudo echo /bin/aspshell >> /etc/shells

$ sudo ln -s /opt/aspera/bin/aspshell /bin/aspshell

$ sudo semanage fcontext -a -t shell_exec_t "/opt/aspera/bin/aspshell"

$ sudo restorecon -v /opt/aspera/bin/aspshell'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56087r818061_chk'
  tag severity: 'medium'
  tag gid: 'V-252631'
  tag rid: 'SV-252631r831526_rule'
  tag stig_id: 'ASP4-TS-020150'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-56037r818062_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
