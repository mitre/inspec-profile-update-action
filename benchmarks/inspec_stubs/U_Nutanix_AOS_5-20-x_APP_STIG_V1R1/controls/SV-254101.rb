control 'SV-254101' do
  title 'Nutanix AOS must prevent nonprivileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing nonprivileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Restricting nonprivileged users also prevents an attacker, who has gained access to a nonprivileged account, from elevating privileges, creating accounts, and performing system checks and maintenance.'
  desc 'check', 'Display a list of configured users and their roles on the Prism UI:

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to "Local User Management".

Validate that only authorized accounts have been assigned the "Cluster Admin" role by comparing the above list against the approved user list provided by the ISSM.

If there are any users assigned the "Cluster Admin" role that have not been authorized by the ISSM, this is a finding.'
  desc 'fix', 'Assign the privileged users identified by the ISSM to the Cluster Admin role.'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57586r846389_chk'
  tag severity: 'medium'
  tag gid: 'V-254101'
  tag rid: 'SV-254101r846391_rule'
  tag stig_id: 'NUTX-AP-000070'
  tag gtitle: 'SRG-APP-000340-AS-000185'
  tag fix_id: 'F-57537r846390_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
