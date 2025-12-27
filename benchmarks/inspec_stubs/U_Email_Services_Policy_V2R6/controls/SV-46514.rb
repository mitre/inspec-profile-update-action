control 'SV-46514' do
  title 'Transaction proxies protecting email domains must interrupt and inspect web traffic on the client access path prior to its entry to the enclave.'
  desc "Separation of email server roles supports operational security for application and protocol services. The HTTP path to web sites is a proven convenience in requiring only a browser to access them, but is simultaneously a well known attack vector for people and applications that would attempt to gain unwelcome admittance to internal networks. 

Web-based email applications, such as Exchange Outlook Web App (OWA), are classified as 'internal' or 'private' web servers. As with all web servers in the DoD, Internet-sourced email requests must be encrypted, authenticated, and proxied prior to permitting the transaction to access internally hosted email data. DoD PKI approved mechanisms for authentication are required for email access in the DoD. Internet-sourced web traffic using TLS encryption is also required, however must have the encryption offloaded, and the transaction interrupted before allowing it into the enclave without some inspection. Multiple products exist that could meet the intent of this requirement, such as combination firewall and proxy servers, multi-tasking load balancers or shared authentication services for Internet-sourced traffic."
  desc 'check', 'For sites not using Internet-sourced email web services, this check is N/A. 

Access the EDSP documentation that describes web email infrastructure. Verify transaction proxies offload and inspect the encryption, and initiate a new security context for the transaction. If the transaction servers perform the required security steps before allowing the transaction to proceed into the enclave, this is not a finding.'
  desc 'fix', 'Install a web security solution using a transaction proxy that offloads and inspects the TLS encryption and continues the transaction in a new security context on behalf of the user for Internet-sourced web mail transactions. Document the solution in the EDSP.'
  impact 0.5
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-43599r1_chk'
  tag severity: 'medium'
  tag gid: 'V-35227'
  tag rid: 'SV-46514r2_rule'
  tag stig_id: 'EMG3-110 Email'
  tag gtitle: 'EMG3-110 Web Application Client Access'
  tag fix_id: 'F-39773r1_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'EBBD-1'
end
