control 'SV-222548' do
  title 'The application password must not be changeable by users other than the administrator or the user with which the password is associated.'
  desc "If the application allows user A to change user B's password,  user B can be locked out of the application, and user A is provided the ability to grant themselves access to the application as user B.  This violates application integrity and availability principles.

Many applications provide a password reset capability that allows the user to reset their password if they forget it.

Protections must be utilized when establishing a password change or reset capability to prevent user A from changing user B's password.

Protection is usually accomplished by having each user provide an out of bounds (OOB) communication address such as a separate email address or SMS/text address (mobile phone) that can be used to transmit password reset/change information.

This  OOB information is usually provided by the user when the user account is created.   The OOB information is validated as part of the user account creation process by sending an account validation request to the OOB address and having the user respond to the request.

Applications must prevent users other than the administrator or the user associated with the account from changing the account password."
  desc 'check', "Review the application documentation and interview application administrator.

Determine if the application utilizes passwords. If the application does not utilize passwords, the requirement is NA.

Identify the processes, commands or web pages the application uses to allow application users to change their own passwords. This includes but is not limited to password resets.

If the application does not allow users to change or reset their passwords, the requirement is NA.

Obtain two application test accounts, referred to here as User A and User B. Access the application as User A. Utilize the application password reset or change processes and determine if User A is allowed to specify or otherwise force a password change for User B.

If User A is allowed to change or force a reset of User B's password, this is a finding."
  desc 'fix', 'Use a CAC to authenticate users instead of using passwords. If application users are prohibited or prevented from obtaining a CAC due to DoD policy requirements and passwords are the only viable option, design the application to utilize a secure password change or password reset process.

Utilize out of band (OOB) communication techniques to communicate password change requests to users.

Ensure verification processes exist that allow users to validate the change request prior to implementing the password change.

Ensure users are only allowed to change their own passwords.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-36247r602304_chk'
  tag severity: 'medium'
  tag gid: 'V-222548'
  tag rid: 'SV-222548r879887_rule'
  tag stig_id: 'APSC-DV-001795'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-36211r865212_fix'
  tag 'documentable'
  tag legacy: ['SV-84767', 'V-70145']
  tag cci: ['CCI-000184']
  tag nist: ['IA-5 h']
end
