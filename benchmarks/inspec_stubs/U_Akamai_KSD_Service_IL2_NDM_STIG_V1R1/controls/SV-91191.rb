control 'SV-91191' do
  title 'The Akamai Luna Portal must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals.

One method of minimizing this risk is to use complex passwords and periodically change them. If the network device does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the passwords could be compromised.

This requirement does not include emergency administration accounts, which are meant for access to the network device in case of failure. These accounts are not required to have maximum password lifetime restrictions.'
  desc 'check', 'Verify the 60-day maximum password lifetime restriction is enforced.

Contact the Akamai Professional Services team to verify the changes at 1-877-4-AKATEC (1-877-425-2832).

If the 60-day maximum password lifetime restriction is not enforced, this is a finding.'
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
  tag check_id: 'C-76155r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76495'
  tag rid: 'SV-91191r1_rule'
  tag stig_id: 'AKSD-DM-000035'
  tag gtitle: 'SRG-APP-000174-NDM-000261'
  tag fix_id: 'F-83173r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
