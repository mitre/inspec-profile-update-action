control 'SRG-NET-000138-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be uniquely identified and authenticated to prevent potential misuse and compromise of the system. 

Sharing of accounts prevents accountability and non-repudiation. Organizational users must be uniquely identified and authenticated for all accesses.'
  desc 'check', 'Verify the Unified Communications Session Manager uniquely identifies all users.

If the Unified Communications Session Manager does not uniquely identify all users, then is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to uniquely identify all users.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000138-VVSM-00101_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000138-VVSM-00101'
  tag rid: 'SRG-NET-000138-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000138-VVSM-00101'
  tag gtitle: 'SRG-NET-000138-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000138-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
