control 'SV-76855' do
  title 'ColdFusion must require a username and password for access by each authorized user access.'
  desc 'Non-repudiation of actions taken is required in order to maintain application integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Non-repudiation protects individuals against later claims by an author of not having authored a particular document, a sender of not having transmitted a message, a receiver of not having received a message, or a signatory of not having signed a document. 

Enforcing non-repudiation of actions requires that each user be identified.  Without this identification, events cannot be traced to a user, and a forensic investigation cannot be conducted to determine what exactly happened and who caused the event to occur.  By forcing users to authenticate, each auditable event can be tied to a user, and a sequence of events for the user can be determined.  This is critical when investigating an issue or an attack.'
  desc 'check', 'Access the "Administrator" page under the "Security" menu within the Administrator Console.

If the "Separate user name and password authentication" is not selected, this is a finding.'
  desc 'fix', 'Access the "Administrator" page under the "Security" menu within the Administrator Console.  Select "Separate user name and password authentication" and select the "Submit Changes" button.'
  impact 0.7
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63169r1_chk'
  tag severity: 'high'
  tag gid: 'V-62365'
  tag rid: 'SV-76855r1_rule'
  tag stig_id: 'CF11-02-000030'
  tag gtitle: 'SRG-APP-000080-AS-000045'
  tag fix_id: 'F-68285r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
