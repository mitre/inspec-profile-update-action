control 'SV-251003' do
  title 'MobileIron Sentry must enforce access restrictions associated with changes to the system components.'
  desc 'Changes to the hardware or software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals should be allowed administrative access to the network device for implementing any changes or upgrades. This requirement applies to updates of the application files, configuration, ACLs, and policy filters.'
  desc 'check', 'Verify that only authorized administrators have permissions for changes, deletions, and updates on the MobileIron Sentry. 

1. Log in to System Manager.
2. Go to Security >> Local Users.
3. Verify no unauthorized users are listed.

If unauthorized users are listed, this is a finding.'
  desc 'fix', 'Configure that only authorized administrators have permissions for changes, deletions, and updates on the MobileIron Sentry. 

1. Log in to System Manager.
2. Go to Security >> identity Source >> Local Users. 
3. Click "Add" to add authorized users.
4. If unauthorized users are listed, click the check box next to the unauthorized user and click "Delete".'
  impact 0.3
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54438r802229_chk'
  tag severity: 'low'
  tag gid: 'V-251003'
  tag rid: 'SV-251003r802231_rule'
  tag stig_id: 'MOIS-ND-000930'
  tag gtitle: 'SRG-APP-000516-NDM-000335'
  tag fix_id: 'F-54392r802230_fix'
  tag 'documentable'
  tag cci: ['CCI-000345', 'CCI-000366']
  tag nist: ['CM-5', 'CM-6 b']
end
