control 'SV-91193' do
  title 'The Akamai Luna Portal must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 

If the network device allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify password reuse for a minimum of five generations is prohibited.

Contact the Akamai Professional Services team to verify the changes at 1-877-4-AKATEC (1-877-425-2832).

If the password reuse for a minimum of five generations is not prohibited, this is a finding.'
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
  tag check_id: 'C-76157r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76497'
  tag rid: 'SV-91193r1_rule'
  tag stig_id: 'AKSD-DM-000036'
  tag gtitle: 'SRG-APP-000165-NDM-000253'
  tag fix_id: 'F-83175r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
