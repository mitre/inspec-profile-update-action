control 'SV-21613' do
  title 'Email domains must be protected by transaction proxy at the client access path.'
  desc "Separation of email server roles supports operational security for application and protocol services. The HTTP path to web sites is a proven convenience in requiring only a browser to access them, but is simultaneously a well known attack vector for people and applications that would attempt to gain unwelcome admittance to internal networks. 

Web-based email applications, such as Exchange Outlook Web App (OWA), are classified as 'internal' or 'private' web servers. As with all web servers in the DoD, Internet-sourced email requests must be encrypted, authenticated, and proxied prior to permitting the transaction to access internally hosted email data. For email domains using Microsoft Exchange Client Access (CA) servers, Microsoft recommends and supports that all email CA servers reside inside enclaves (rather than a DMZ location) where firewalls would separate them from the other email servers. DoD PKI approved mechanisms for authentication are required for email access in the DoD. Multiple products exist that could meet the intent of this requirement, such as combination firewall and proxy servers, multi-tasking load balancers or shared authentication services for Internet-sourced traffic."
  desc 'check', 'For sites not using Internet-sourced email web services, this check is N/A. 

Access the EDSP documentation that describes web email infrastructure. Confirm the architecture places the CA server inside the enclave and a transaction proxy residing in the DMZ. Verify DoD approved multi-factor authentication tokens (e.g., Common Access Card (CAC) for unclassified systems) are required at the transaction proxy. If the email domain employs the required architecture, this is not a finding.'
  desc 'fix', 'Install a web security solution requiring DoD approved multi-factor authentication tokens, with architecture placing the CA server inside the enclave, and the transaction proxy residing in the DMZ. Document the solution in the EDSP.'
  impact 0.7
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-23796r6_chk'
  tag severity: 'high'
  tag gid: 'V-19548'
  tag rid: 'SV-21613r3_rule'
  tag stig_id: 'EMG3-108 EMail'
  tag gtitle: 'EMG3-108 Web Application Client Access'
  tag fix_id: 'F-20244r4_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'EBBD-1'
end
