control 'SV-228403' do
  title 'Exchange services must be documented and unnecessary services must be removed or disabled.'
  desc 'Unneeded but running services offer attackers an enhanced attack profile, and attackers are constantly watching to discover open ports with running services. By analyzing and disabling unneeded services, the associated open ports become unresponsive to outside queries, and servers become more secure as a result.
 
Exchange Server has role-based server deployment to enable protocol path control and logical separation of network traffic types.

For example, a server implemented in the Client Access role (i.e., Outlook Web App [OWA]) is configured and tuned as a web server using web protocols. A client access server exposes only web protocols (HTTP/HTTPS), enabling system administrators to optimize the protocol path and disable all services unnecessary for Exchange web services. Similarly, servers created to host mailboxes are dedicated to that task and must operate only the services needed for mailbox hosting. (Exchange servers must also operate some web services, but only to the degree that Exchange requires the IIS engine in order to function).

Because Post Office Protocol 3 (POP3) and Internet Message Access Protocol 4 (IMAP4) clients are not included in the standard desktop offering, they must be disabled. While IMAP4 is restricted, IMAP Secure is not restricted and does not apply to this requirement.'
  desc 'check', "Review the Email Domain Security Plan (EDSP).

Note: Required services will vary among organizations and will vary depending on the role of the individual system. Organizations will develop their own list of services, which will be documented and justified with the Information System Security Officer (ISSO). The site’s list will be provided for any security review. Services that are common to multiple systems can be addressed in one document. Exceptions for individual systems should be identified separately by system.

Open a Windows PowerShell and enter the following command:

Get-Service | Where-Object {$_.status -eq 'running'}

Note: The command returns a list of installed services and the status of that service. 

If the services required are not documented in the EDSP, this is a finding.

If any undocumented or unnecessary services are running, this is a finding."
  desc 'fix', 'Update the EDSP to specify the services required for the system to function. 

Remove or disable any services that are not required.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30636r497005_chk'
  tag severity: 'medium'
  tag gid: 'V-228403'
  tag rid: 'SV-228403r612748_rule'
  tag stig_id: 'EX16-MB-000600'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-30621r497006_fix'
  tag 'documentable'
  tag legacy: ['SV-95443', 'V-80733']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
