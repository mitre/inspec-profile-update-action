control 'SV-251343' do
  title 'If an automated scheduler is used to provide updates to the sensors, an account on the file server must be defined that will provide access to the signatures only to the sensors.'
  desc 'In a large scale IDPS deployment, it is common to have an automated update process implemented. This is accomplished by having the updates downloaded on a dedicated secure file server within the management network. The file server should be configured to allow read-only access to the files within the directory on which the signature packs are placed, and then only from the account that the sensors will use. The sensors can then be configured to automatically check the secure file server periodically to look for the new signature packs and to update themselves.'
  desc 'check', 'Review the file server accounts and determine if the accounts with read access to the IDPS signatures are provided only to the IDPS sensors.

If there are accounts other than those allocated for the IDPS sensors providing access to the signatures, this is a finding.'
  desc 'fix', 'Secure the signatures from access to accounts for IDS updates.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54778r805982_chk'
  tag severity: 'medium'
  tag gid: 'V-251343'
  tag rid: 'SV-251343r805984_rule'
  tag stig_id: 'NET-IDPS-030'
  tag gtitle: 'NET-IDPS-030'
  tag fix_id: 'F-54731r805983_fix'
  tag 'documentable'
  tag legacy: ['V-18507', 'SV-20042']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
