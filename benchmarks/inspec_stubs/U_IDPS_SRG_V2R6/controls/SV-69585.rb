control 'SV-69585' do
  title 'The IDPS must be configured to remove or disable non-essential capabilities which are not required for operation or not related to IDPS functionality (e.g., DNS, email client or server, FTP server, or web server).'
  desc 'An IDPS can be capable of providing a wide variety of capabilities. Not all of these capabilities are necessary. Unnecessary services, functions, and applications increase the attack surface (sum of attack vectors) of a system. These unnecessary capabilities are often overlooked and therefore may remain unsecured.'
  desc 'check', 'Have the SCA display the services running on the IDPS components. Review the IDPS configuration to determine if non-essential capabilities not required for operation, or not related to IDPS functionality (e.g., DNS, email client or server, FTP server, or web server) are enabled. 

If the IDPS is not configured to remove or disable non-essential capabilities which are not required for operation or not related to IDPS functionality (e.g., DNS, email client or server, FTP server, or web server), this is a finding.'
  desc 'fix', 'Remove or disable non-essential capabilities from the IDPS. Removal is recommended since the service or function may be inadvertently enabled. However, if removal is not possible, disable the service or function. Document all necessary services.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55961r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55339'
  tag rid: 'SV-69585r1_rule'
  tag stig_id: 'SRG-NET-000131-IDPS-00011'
  tag gtitle: 'SRG-NET-000131-IDPS-00011'
  tag fix_id: 'F-60205r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
