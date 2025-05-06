control 'SV-76857' do
  title 'ColdFusion must require each user to authenticate with a unique account.'
  desc 'Non-repudiation of actions taken is required in order to maintain application integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Non-repudiation protects individuals against later claims by an author of not having authored a particular document, a sender of not having transmitted a message, a receiver of not having received a message, or a signatory of not having signed a document. 

Enforcing non-repudiation of actions requires that each user be uniquely identified.  Without this identification, events cannot be traced to a particular user, and a forensic investigation cannot be conducted to determine what exactly happened and who caused the event to occur.  By forcing each user to authenticate using a unique account, each auditable event can be tied to a user, and a sequence of events for the user can be determined.  This is critical when investigating an issue or an attack.'
  desc 'check', 'Review the users within the "User Manager" page under the "Security" menu.

If users are not defined, this is a finding.'
  desc 'fix', 'Create user accounts within the "User Manager" page under the "Security" menu for those users that need access to the Administrator Console.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63171r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62367'
  tag rid: 'SV-76857r1_rule'
  tag stig_id: 'CF11-02-000031'
  tag gtitle: 'SRG-APP-000080-AS-000045'
  tag fix_id: 'F-68287r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
