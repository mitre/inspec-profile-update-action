control 'SV-218015' do
  title 'The Automatic Bug Reporting Tool (abrtd) service must not be running.'
  desc "Mishandling crash data could expose sensitive information about vulnerabilities in software executing on the local machine, as well as sensitive information from within a process's address space or registers."
  desc 'check', 'To check that the "abrtd" service is disabled in system boot configuration, run the following command: 

# chkconfig "abrtd" --list

Output should indicate the "abrtd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "abrtd" --list
"abrtd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "abrtd" is disabled through current runtime configuration: 

# service abrtd status

If the service is disabled the command will return the following output: 

abrtd is stopped


If the service is running, this is a finding.'
  desc 'fix', 'The Automatic Bug Reporting Tool ("abrtd") daemon collects and reports crash data when an application crash is detected. Using a variety of plugins, abrtd can email crash reports to system administrators, log crash reports to files, or forward crash reports to a centralized issue tracking system such as RHTSupport. The "abrtd" service can be disabled with the following commands: 

# chkconfig abrtd off
# service abrtd stop'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19496r377060_chk'
  tag severity: 'low'
  tag gid: 'V-218015'
  tag rid: 'SV-218015r603264_rule'
  tag stig_id: 'RHEL-06-000261'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-19494r377061_fix'
  tag 'documentable'
  tag legacy: ['SV-50441', 'V-38640']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
