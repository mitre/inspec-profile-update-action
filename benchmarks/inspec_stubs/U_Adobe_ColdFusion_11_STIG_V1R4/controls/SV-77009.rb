control 'SV-77009' do
  title 'ColdFusion must prevent JavaScript Object Notation (JSON) hijacking of data.'
  desc 'Information can be either unintentionally or maliciously disclosed if not protected during preparation for transmission.  An easy way to protect data during preparation for transmission is to use non-default identifiers for data.  An example is for JavaScript Object Notation (JSON) to use a prefix other than the default "JSON" prefix, signifying to an attacker an array of data is following.

JSON is a lightweight data-interchange format.'
  desc 'check', 'Within the Administrator Console, navigate to the "Settings" page under the "Server Settings" menu.

If the "Prefix serialized JSON with" is unchecked, this is a finding.'
  desc 'fix', 'Navigate to the "Settings" page under the "Server Settings" menu.  Check "Prefix serialized JSON with" and select the "Submit Changes" button.'
  impact 0.7
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63323r1_chk'
  tag severity: 'high'
  tag gid: 'V-62519'
  tag rid: 'SV-77009r1_rule'
  tag stig_id: 'CF11-05-000200'
  tag gtitle: 'SRG-APP-000441-AS-000258'
  tag fix_id: 'F-68439r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
