control 'SV-18886' do
  title 'User Guides and documentation packages must be developed and distributed to users operating VTC endpoints.'
  desc 'User documentation packages should include user agreements, training documentation, and endpoint user guides that reiterate the training information and the agreed upon User Agreement policies. The Endpoint User Guides should also provide additional information to include system or device operations, usage procedures for features, and IA measures as required to address the protection of both meeting related and non-meeting related information'
  desc 'check', 'Review site documentation to confirm user guides and documentation packages are developed and distributed to users operating VTC endpoints, to include conference room systems, that provides the following information:
- Reiterates the policies and restrictions agreed to when the user’s agreement was signed upon receiving the VTC endpoint of authorization to use one.
- Provides cautions and notice of the non-assured nature of VTC communications so that C2 users are aware and reminded regarding the use of this communications media for C2.
- Provides instruction regarding the proper and safe use of a VTC endpoint’s or conference room system’s audio and video capabilities such that the appropriate confidentiality of meeting related and non-meeting related information is maintained.
- Provides instruction regarding the proper and safe use of document and desktop sharing when using a PC connected to a VTC endpoint such that the appropriate confidentiality of meeting related and non-meeting related information is maintained.
- Provides instruction regarding the safeguarding of meeting related and non-meeting related sensitive and/or classified information

If user guides and documentation packages are not developed and distributed to users operating VTC endpoints, this is a finding.'
  desc 'fix', 'Implement a policy or procedure for User Guides and documentation packages to be developed and distributed to users operating VTC endpoints, to include conference room systems that provide the following information: 
- Reiterates the policies and restrictions agreed to when the user’s agreement was signed upon receiving the VTC endpoint of authorization to use one.
- Provides cautions and notice of the non-assured nature of VTC communications so that C2 users are aware and reminded regarding the use of this communications media for C2.
- Provides instruction regarding the proper and safe use of a VTC endpoint’s or conference room system’s audio and video capabilities such that the appropriate confidentiality of meeting related and non-meeting related information is maintained.
- Provides instruction regarding the proper and safe use of document and desktop sharing when using a PC connected to a VTC endpoint such that the appropriate confidentiality of meeting related and non-meeting related information is maintained.
- Provides instruction regarding the safeguarding of meeting related and non-meeting related sensitive and/or classified information.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18982r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17712'
  tag rid: 'SV-18886r2_rule'
  tag stig_id: 'RTS-VTC 3740.00'
  tag gtitle: 'RTS-VTC 3740'
  tag fix_id: 'F-17609r3_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Other']
end
