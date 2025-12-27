control 'SV-234872' do
  title 'The SUSE operating system must never automatically remove or disable emergency administrator accounts.'
  desc "Emergency accounts are privileged accounts that are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability. 

Emergency accounts are different from infrequently used accounts (i.e., local logon accounts used by the organization's system administrators when network or normal logon/access is not available). Infrequently used accounts are not subject to automatic termination dates. Emergency accounts are accounts created in response to crisis situations, usually for use by maintenance personnel. The automatic expiration or disabling time period may be extended as needed until the crisis is resolved; however, it must not be extended indefinitely. A permanent account should be established for privileged users who need long-term maintenance accounts.

To address access requirements the SUSE operating system can be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements."
  desc 'check', 'Verify the SUSE operating system is configured such that emergency administrator accounts are never automatically removed or disabled. 

Note: Root is typically the "account of last resort" on a system and is also used as the example emergency administrator account. If another account is being used as the emergency administrator account, the command should be used against that account. 

Check to see if the root account password or account expires with the following command:

> sudo chage -l [Emergency_Administrator]

Password expires:never

If "Password expires" or "Account expires" is set to anything other than "never", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to never automatically remove or disable emergency administrator accounts.

Replace "[Emergency_Administrator]" in the following command with the correct emergency administrator account. Run the following command as an administrator:

> sudo chage -I -1 -M 99999 [Emergency_Administrator]'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38060r618885_chk'
  tag severity: 'medium'
  tag gid: 'V-234872'
  tag rid: 'SV-234872r622137_rule'
  tag stig_id: 'SLES-15-020060'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag fix_id: 'F-38023r618886_fix'
  tag 'documentable'
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
