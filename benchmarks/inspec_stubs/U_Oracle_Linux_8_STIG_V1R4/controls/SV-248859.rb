control 'SV-248859' do
  title 'The OL 8 "fapolicy" module must be installed.'
  desc %q(The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting. 
 
Using a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities. Verification of whitelisted software occurs prior to execution or at system startup. 
 
Users' home directories/folders may contain information of a sensitive nature. Non-privileged users should coordinate any sharing of information with a System Administrator through shared resources. 
 
OL 8 ships with many optional packages. One such package is a file access policy daemon called "fapolicyd". This is a userspace daemon that determines access rights to files based on attributes of the process and file. It can be used to either blacklist or whitelist processes or file access. 
 
Proceed with caution with enforcing the use of this daemon. Improper configuration may render the system non-functional. The "fapolicyd" API is not namespace aware and can cause issues when launching or running containers.

)
  desc 'check', 'Verify the OL 8 "fapolicyd" is installed.
 
Check that "fapolicyd" is installed with the following command:
 
$ sudo yum list installed fapolicyd 
 
Installed Packages 
fapolicyd.x86_64 
 
If "fapolicyd" is not installed, this is a finding.'
  desc 'fix', 'Install "fapolicyd" with the following command: 
 
$ sudo yum install fapolicyd.x86_64'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52293r780141_chk'
  tag severity: 'medium'
  tag gid: 'V-248859'
  tag rid: 'SV-248859r853868_rule'
  tag stig_id: 'OL08-00-040135'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-52247r780142_fix'
  tag satisfies: ['SRG-OS-000368-GPOS-00154', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag cci: ['CCI-001764', 'CCI-001774']
  tag nist: ['CM-7 (2)', 'CM-7 (5) (b)']
end
