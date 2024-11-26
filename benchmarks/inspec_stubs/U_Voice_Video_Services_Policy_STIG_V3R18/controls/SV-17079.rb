control 'SV-17079' do
  title 'A user guide identifying the proper use of Unified Capabilities (UC) soft client applications must be provided to UC soft client users.'
  desc "User agreements must be accompanied with a combination of user training and user guides reinforcing the organization's policies and prohibitions for UC soft clients (voice, video, and collaboration communications software clients). The training and guides should also provide additional information such as how to operate the UC soft client and implement cybersecurity features as required. Other topics that should be contained in a user guide include the use of webcams and microphones with both UC soft clients and hardware end instruments when used in a classified environment or where classified discussions occur.

The user guide must contain a discussion pertaining to the use of UC soft client applications for assured service C2 communications. Cautions regarding the potentially unreliable nature of these communications applications or methods must be included in user guides so that C2 users are aware of, and reminded of, the non-assured service nature of these communications methods."
  desc 'check', 'Interview the ISSO to validate compliance with the following requirement:

Verify a user guide is developed and distributed to users of UC soft client applications minimally providing the following information:
- Review the policies and restrictions agreed to when the user agreement was signed upon receiving the communications application.
- Provide a caution notice discussing the non-assured nature of UC soft client applications for C2 user awareness that for assured service a UC soft client should not be the primary method of communications.
- Provide instruction for the proper and safe use of webcams or built-in cameras when used in a classified environment to prevent viewing classified work or classified material over non-secure networks.
- Provide instruction for the proper and safe use of speakerphones or built-in microphones when used in a classified environment to prevent hearing classified discussions over non-secure networks. 
- Provide instruction regarding the proper and safe use of presentation, document, and desktop sharing.

Inspect the user guide for the proper use of UC soft client and validate users received this guide by interviewing a random sampling of users. If the user guide is deficient in content or the guide is not provided to users, this is a finding.'
  desc 'fix', 'Develop and distribute a user guide to users of UC soft client applications minimally providing the following information:
- Review the policies and restrictions agreed to when the user agreement was signed upon receiving the communications application.
- Provide a caution notice discussing the non-assured nature of UC soft client applications for C2 user awareness that for assured service a UC soft client should not be the primary method of communications.
- Provide instruction for the proper and safe use of webcams or built-in cameras when used in a classified environment to prevent viewing classified work or classified material over non-secure networks.
- Provide instruction for the proper and safe use of speakerphones or built-in microphones when used in a classified environment to prevent hearing classified discussions over non-secure networks. 
- Provide instruction regarding the proper and safe use of presentation, document, and desktop sharing.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17134r3_chk'
  tag severity: 'low'
  tag gid: 'V-16091'
  tag rid: 'SV-17079r3_rule'
  tag stig_id: 'VVoIP 1330'
  tag gtitle: 'Provide UC soft client user guide'
  tag fix_id: 'F-16196r3_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
end
