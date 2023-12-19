control 'SRG-NET-000138-VVEP-00029_rule' do
  title 'The Unified Communications Endpoint must be configured to uniquely identify participating users.'
  desc "To assure accountability and prevent unauthenticated access, users must be identified to prevent potential misuse and compromise of the system. The Unified Communications Endpoint must display the source of an incoming call and the participant's identity to aid the user in deciding whether to answer a call. The information potentially at risk is that which can be seen in the physical area of the Unified Communications Endpoint or carried by the conference in which it is participating. 

This does not apply to authentication for the purpose of configuring the device itself (i.e., device management)."
  desc 'check', 'Verify the Unified Communications Endpoint uniquely identifies participating users. Identification must be visible and displayed locally.

If the Unified Communications Endpoint does not uniquely identify participating users, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to uniquely identify participating users.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000138-VVEP-00029_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000138-VVEP-00029'
  tag rid: 'SRG-NET-000138-VVEP-00029_rule'
  tag stig_id: 'SRG-NET-000138-VVEP-00029'
  tag gtitle: 'SRG-NET-000138-VVEP-00029'
  tag fix_id: 'F-SRG-NET-000138-VVEP-00029_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
