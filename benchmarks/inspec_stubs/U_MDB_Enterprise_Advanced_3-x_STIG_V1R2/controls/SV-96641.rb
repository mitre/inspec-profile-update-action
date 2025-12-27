control 'SV-96641' do
  title 'MongoDB must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Normally, with PKI authentication, the interaction with the user for authentication will be handled by a software component separate from MongoDB, such as ActivIdentity ActivClient. However, in cases where MongoDB controls the interaction, this requirement applies.

To prevent the compromise of authentication information such as passwords and PINs during the authentication process, the feedback from the system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism.

Obfuscation of user-provided authentication secrets when typed into the system is a method used in addressing this risk.

Displaying asterisks when a user types in a password or a smart card PIN is an example of obscuring feedback of authentication secrets.

This calls for review of applications, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.'
  desc 'check', 'For the MongoDB command-line tools "mongo shell", "mongodump", "mongorestore", "mongoimport", "mongoexport", which cannot be configured not to accept a plain-text password, and any other essential tool with the same limitation, verify that the system documentation explains the need for the tool, who uses it, and any relevant mitigations and that AO approval has been obtained. 

If it is not documented, this is a finding. 

Request evidence that all users of these MongoDB command-line tools are trained in the use of the "-p" option plain-text password option and how to keep the password protected from unauthorized viewing/capture and that they adhere to this practice. 

If evidence of training does not exist, this is a finding.'
  desc 'fix', 'For the "mongo shell", "mongodump", "mongorestore", "mongoimport", "mongoexport", which can accept a plain-text password, and any other essential tool with the same limitation: 

Document the need for it, who uses it, and any relevant mitigations, and obtain AO approval. 

Train all users of the tool in the nature of using the plain-text password option and in how to keep the password protected from unauthorized viewing/capture and document they have been trained.'
  impact 0.7
  ref 'DPMS Target MongoDB 3.x'
  tag check_id: 'C-81719r1_chk'
  tag severity: 'high'
  tag gid: 'V-81927'
  tag rid: 'SV-96641r1_rule'
  tag stig_id: 'MD3X-00-000800'
  tag gtitle: 'SRG-APP-000178-DB-000083'
  tag fix_id: 'F-88777r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
