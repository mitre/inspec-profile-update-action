control 'SV-252642' do
  title 'The IBM Aspera High-Speed Transfer Server must restrict the transfer user(s) to the "aspshell".'
  desc "By default, all system users can establish a FASP connection and are only restricted by file permissions. Restrict the user's file operations by assigning them to use aspshell, which permits only the following operations:
Running Aspera uploads and downloads to or from this computer.
Establishing connections in the application.
Browsing, listing, creating, renaming, or deleting contents.

To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.
Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses except the following.

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication.

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

This requirement applies to ALGs that provide user proxy services, including identification and authentication. This service must use the site's directory service (e.g., Active Directory). Directory services must not be installed onto the gateway."
  desc 'check', 'Verify the Aspera High-Speed Transfer Server restricts the transfer user(s) to the "aspshell" with the following command:

$ sudo grep <username> /etc/passwd

<username>:x:1001:1001:...:/home/<username>:/bin/aspshell

If the transfer user is not limited to the "aspshell", this is a finding.'
  desc 'fix', 'Configure the Aspera High-Speed Transfer Server to restrict the transfer user(s) to the "aspshell" with the following command:

$ sudo usermod -s /bin/aspshell <username>'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56098r818094_chk'
  tag severity: 'medium'
  tag gid: 'V-252642'
  tag rid: 'SV-252642r818096_rule'
  tag stig_id: 'ASP4-TS-020260'
  tag gtitle: 'SRG-NET-000138-ALG-000063'
  tag fix_id: 'F-56048r818095_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
