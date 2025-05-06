control 'SV-21609' do
  title 'Email domains must be protected by an Edge Server at the email transport path.'
  desc 'Separation of roles supports operational security for application and protocol services. Since 2006, Microsoft best practices had taken the direction of creating operational “roles” for servers within email services. The Edge Transport server role (also called an Email Secure Gateway) was created to focus authentication and sanitization tasks in one server, to provide Internet facing protection for internal email servers. 

In the email services infrastructure, it has become imperative that inbound messages be examined prior to their being forwarded into the enclave, primarily due to the amount of SPAM and malware contained in the message stream. Similarly, outbound messages must be examined, so an organization might locate, or perhaps intercept, messages with potential data spillage of sensitive or important information. The Edge Transport email server role, which could be implemented using a number of comparable products, is designed to perform protective measures for both inbound and outbound messages. Its charter is to face the Internet, and to scrutinize all SMTP traffic, to determine whether to grant continued passage for messages to their destination. 

Inbound email sanitization steps include (but are not limited to) processes, such as sender authentication and evaluation, content scoring (SPAM, spoofing, and phishing detection), antivirus sanitization and quarantine services, and results reporting. Outbound messages are typically examined for SPAM and malware origination. 

Failure to implement an Email Edge Transport server role may increase risk of compromise by allowing undesirable inbound messages could to reach the internal servers and networks. Failure to examine outbound traffic may increase risk of domain blacklisting if SPAM or malware is traced back to the source domain. Attempting to sanitize email after it arrives inside the domain is not an acceptable or effective security measure. By using an Edge Transport Server (Email Secure Gateway), any SMTP-specific attack vectors are more optimally secured.'
  desc 'check', 'Access EDSP documentation that describes the infrastructure for email services. Verify an Edge Transport Server (or Email Secure Gateway) is installed and active on the network. Ensure all inbound and outbound email messages pass through and are examined as required.

If the email domain employs an Edge Transport Server Role that performs the required protection, this is not a finding.'
  desc 'fix', 'Install and configure an Edge Transport Server role in the email infrastructure, configured to perform specified sanitization processes. Ensure all inbound and outbound SMTP traffic passes through this server role. Document the Edge Transport Server specifics in the EDSP.'
  impact 0.7
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-23795r6_chk'
  tag severity: 'high'
  tag gid: 'V-19546'
  tag rid: 'SV-21609r3_rule'
  tag stig_id: 'EMG3-106 Email'
  tag gtitle: 'EMG3-106 Edge Transport Server Required'
  tag fix_id: 'F-20241r3_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'EBBD-1'
end
