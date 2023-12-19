control 'SV-100359' do
  title 'The SLES for vRealize must be configured such that emergency administrator accounts are never automatically removed or disabled.'
  desc 'Emergency administrator accounts are privileged accounts that are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability. 

Emergency administrator accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon/access is not available). Infrequently used accounts also remain available and are not subject to automatic termination dates. However, an emergency administrator account is normally a different account that is created for use by vendors or system maintainers.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'For each emergency administrator account run the following command:

chage -l [user]

If the output shows an expiration date for the account, this is a finding.'
  desc 'fix', 'For each emergency administrator account run the following command to remove the expiration: 

chage -E -1 [user]'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89401r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89709'
  tag rid: 'SV-100359r1_rule'
  tag stig_id: 'VRAU-SL-000755'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag fix_id: 'F-96451r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
