control 'SV-91183' do
  title 'If multifactor authentication is not supported and passwords must be used, the Akamai Luna Portal must enforce password complexity by requiring that at least one upper-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the password must contain at least one upper-case character.

Contact the Akamai Professional Services team to verify the changes at 1-877-4-AKATEC (1-877-425-2832).

If the password does not require at least one upper-case character, this is a finding.'
  desc 'fix', %q(Open a ticket through the Akamai Customer Portal (Luna), https://control.akamai.com
 
Select the “Support” link, under the “OPEN A CASE” section, select "Business Support Issue or Question".
The "Area" field should be "General Account Management".
Service should be "Product Support".
Once selected a form will load where the subject should be "Password Security Policy Exception Request"
The description should contain the following information with all fields completed.  (Please note that if the character limit is exceeded then the following may be submitted as an attachment.)
 
-------------
Requester's name:
 
Requester's title:
 
Requester's organization/command:
 
We request the following exception(s) to the standard Akamai Luna password management policy to be applied to all accounts.
 
    - Force password rotations to occur at least every 60 days.
    - Disable any inactive accounts if they have not been used for 90 consecutive days.
    - Limit the number of consecutive invalid login attempts to 3.
    - Enforce a minimum length of 15 characters.
    - Require that at least one upper-case character be used.
    - Require that at least one lower-case character be used.
    - Require that at least one numeric character be used.
    - Require that at least one special character be used.
    - Prevent password reuse for at least 5 generations.
  
We understand this is a divergence from the standard, recommended Luna security policy.
 
Please submit this password policy exception request to the Akamai InfoSec team for review.  It has been approved by the security officer or administrator for the organization.  The following is the approver's information:
 
Approver's Name: 
 
Approver's Title:
(must security personnel for the organization)
 
Approver's Contact Information (necessary to validate this request):
 
      Phone: 
 
      E-mail:
-------------
 
Complete the contact information fields if they haven't been prepopulated, and then click "Create Case")
  impact 0.5
  ref 'DPMS Target Akamai Edge Security NDM'
  tag check_id: 'C-76147r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76487'
  tag rid: 'SV-91183r1_rule'
  tag stig_id: 'AKSD-DM-000029'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag fix_id: 'F-83165r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
