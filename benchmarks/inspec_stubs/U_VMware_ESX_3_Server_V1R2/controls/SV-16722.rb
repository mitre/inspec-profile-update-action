control 'SV-16722' do
  title 'ESX Server is not configured in accordance with the UNIX STIG.'
  desc 'The UNIX Checklist must first be verified against all ESX Servers, since the ESX Server service console is considered a modified Linux distribution. DISA Field Security Operations has developed the UNIX SRR scripts to evaluate all UNIX machines against the UNIX STIG requirements. The UNIX SRR scripts determine all the open operating system vulnerabilities. The UNIX SRR Scripts are not supported against the ESX Server platform, but they can still be run to verify compliance.  If the UNIX SRR Scripts are used, system administrators should verify all results against the UNIX Checklist to ensure results are accurate.'
  desc 'check', '1. Use the UNIX Checklist to manually verify compliance to the UNIX requirements.

OR

2. On the ESX Server service console, perform the following command:
# find / -iname Script.*
 
If the command brings back an output, review the result files that are located under (Script.Month)/hostname.  Review the results and verify that only GEN003540 and GEN006640 are open.  If any other findings are open this is a finding.

If the command does not return a result, then the reviewer will have to run the UNIX SRR scripts from the CD. If there are any open findings other than GEN003540 and GEN006640 this is a finding.

The following open findings will NOT be applicable when running the UNIX SRR against the ESX Server service console:  

GEN003540 - Executable Stack
GEN003540 (CAT II) OPEN
FINDING DESCRIPTION GEN003540:  The SA will ensure the executable stack is disabled.
SYSTEM CONFIGURATION: VMware ESX Server 3 does not support this configuration. The kernel has executable stack enabled.  

GEN006640 - Virus Protection
GEN006640 (CAT I) OPEN
FINDING DESCRIPTION GEN006640: An approved DoD virus scan program in not used and/or updated.
SYSTEM CONFIGURATION: Unable to install McAfee Virus scan command-line tool on VMware ESX.  Some of the prerequisite filesets for this product conflict with the versions required by VMware Operating System filesets.

Note: The UNIX SRR Scripts are not supported on the ESX Server.  If used, please verify all results and findings against the UNIX Checklist.'
  desc 'fix', 'Manually check the UNIX requirements against the ESX Server or run the UNIX SRR scripts against the ESX Server service console.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-15969r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15783'
  tag rid: 'SV-16722r1_rule'
  tag stig_id: 'ESX0010'
  tag gtitle: 'ESX Server not compliant with UNIX STIG.'
  tag fix_id: 'F-15724r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
