control 'SV-216062' do
  title 'The operating system must be configured to provide essential capabilities.'
  desc 'Operating systems are capable of providing a wide variety of functions and services. Execution must be disabled based on organization-defined specifications.'
  desc 'check', 'Identify the packages installed on the system. 

# pkg list

Any unauthorized software packages listed in the output are a finding.'
  desc 'fix', 'The Software Installation profile is required.

Identify packages installed on the system:

# pkg list

uninstall unauthorized packages:

# pfexec pkg uninstall [ package name]'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17300r372568_chk'
  tag severity: 'medium'
  tag gid: 'V-216062'
  tag rid: 'SV-216062r603268_rule'
  tag stig_id: 'SOL-11.1-020220'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-17298r372569_fix'
  tag 'documentable'
  tag legacy: ['V-47925', 'SV-60797']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
