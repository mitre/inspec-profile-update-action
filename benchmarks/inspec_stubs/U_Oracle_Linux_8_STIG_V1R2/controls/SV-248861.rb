control 'SV-248861' do
  title 'The OL 8 fapolicy module must be configured to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.'
  desc %q(The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting. 
 
Using a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities. Verification of whitelisted software occurs prior to execution or at system startup. 
 
Users' home directories/folders may contain information of a sensitive nature. Non-privileged users should coordinate any sharing of information with a System Administrator through shared resources. 
 
OL 8 ships with many optional packages. One such package is a file access policy daemon called "fapolicyd". This is a userspace daemon that determines access rights to files based on attributes of the process and file. It can be used to either blacklist or whitelist processes or file access. 
 
Proceed with caution with enforcing the use of this daemon. Improper configuration may render the system non-functional. The "fapolicyd" API is not namespace aware and can cause issues when launching or running containers.

)
  desc 'check', 'Verify the OL 8 "fapolicyd" employs a deny-all, permit-by-exception policy.

Check that "fapolicyd" is in enforcement mode with the following command:

$ sudo grep permissive /etc/fapolicyd/fapolicyd.conf

permissive = 0

Check that fapolicyd employs a deny-all policy on system mounts with the following command:

$ sudo tail /etc/fapolicyd/fapolicyd.rules

allow exe=/usr/bin/python3.7 : ftype=text/x-python
deny_audit perm=any pattern=ld_so : all
deny perm=any all : all

If fapolicyd is not running in enforcement mode with a deny-all, permit-by-exception policy, this is a finding.'
  desc 'fix', 'Configure OL 8 to employ a deny-all, permit-by-exception application whitelisting policy with "fapolicyd".

With the "fapolicyd" installed and enabled, configure the daemon to function in permissive mode until the whitelist is built correctly to avoid system lockout. Do this by editing the "/etc/fapolicyd/fapolicyd.conf" file with the following line:

permissive = 1

Build the whitelist in the "/etc/fapolicyd/fapolicyd.rules" file ensuring the last rule is "deny perm=any all : all".

Once it is determined the whitelist is built correctly, set the fapolicyd to enforcing mode by editing the "permissive" line in the /etc/fapolicyd/fapolicyd.conf file.

permissive = 0'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52295r818700_chk'
  tag severity: 'medium'
  tag gid: 'V-248861'
  tag rid: 'SV-248861r818702_rule'
  tag stig_id: 'OL08-00-040137'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-52249r818701_fix'
  tag satisfies: ['SRG-OS-000368-GPOS-00154', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag cci: ['CCI-001764', 'CCI-001774']
  tag nist: ['CM-7 (2)', 'CM-7 (5) (b)']
end
